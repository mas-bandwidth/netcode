/*
    fuzz netcode_read_packet, the primary hostile-input surface: every byte a netcode
    server or client accepts off a socket goes through this function.

    mode 0: feed raw fuzz data straight into netcode_read_packet. this exercises all
            parsing and rejection ahead of AEAD authentication (a fuzzer cannot forge
            a valid MAC, so decryption is expected to fail here).

    mode 1: build a packet from fuzz-derived fields, write and encrypt it with the
            real keys, optionally corrupt one byte, then read it back. this drives
            the post-decryption parsing, and asserts the round-trip property: an
            uncorrupted packet written by netcode_write_packet must read back with
            the same type and sequence. connection requests get their connect token
            encrypted with the real private key, so the full request path including
            token decrypt and read is covered.
*/

#include "netcode.c"
#include "fuzz.h"

#define FUZZ_PROTOCOL_ID 0x1122334455667788ULL

static int initialized = 0;
static uint8_t packet_key[NETCODE_KEY_BYTES];
static uint8_t private_key[NETCODE_KEY_BYTES];

static void fuzz_initialize()
{
    if ( initialized )
        return;
    netcode_init();
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    memset( packet_key, 0xAA, sizeof( packet_key ) );
    memset( private_key, 0xBB, sizeof( private_key ) );
    initialized = 1;
}

static void * fuzz_call_read_packet( uint8_t * buffer, int buffer_length, uint64_t * sequence, struct netcode_replay_protection_t * replay_protection )
{
    uint8_t allowed_packets[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packets, 1, sizeof( allowed_packets ) );

    return netcode_read_packet( buffer,
                                buffer_length,
                                sequence,
                                packet_key,
                                FUZZ_PROTOCOL_ID,
                                0,                      // current timestamp: zero so fuzz-chosen expire timestamps pass
                                private_key,
                                allowed_packets,
                                replay_protection,
                                NULL,
                                NULL );
}

static void fuzz_raw_packet( struct fuzz_input_t * in )
{
    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    int packet_bytes = (int) ( in->size - in->offset );
    if ( packet_bytes > NETCODE_MAX_PACKET_BYTES )
        packet_bytes = NETCODE_MAX_PACKET_BYTES;

    fuzz_read_bytes( in, buffer, packet_bytes );

    struct netcode_replay_protection_t replay_protection;
    netcode_replay_protection_reset( &replay_protection );

    uint64_t sequence;
    void * packet = fuzz_call_read_packet( buffer, packet_bytes, &sequence, &replay_protection );
    if ( packet )
        free( packet );
}

static void fuzz_round_trip_packet( struct fuzz_input_t * in )
{
    uint8_t packet_type = fuzz_read_u8( in ) % NETCODE_CONNECTION_NUM_PACKETS;
    uint64_t sequence = fuzz_read_u64( in );
    uint8_t corrupt = fuzz_read_u8( in ) & 1;
    uint16_t corrupt_offset = fuzz_read_u16( in );
    uint8_t corrupt_xor = fuzz_read_u8( in );

    // build the packet struct for the chosen type from fuzz input

    struct netcode_connection_request_packet_t request_packet;
    struct netcode_connection_denied_packet_t denied_packet;
    struct netcode_connection_challenge_packet_t challenge_packet;
    struct netcode_connection_response_packet_t response_packet;
    struct netcode_connection_keep_alive_packet_t keep_alive_packet;
    struct netcode_connection_disconnect_packet_t disconnect_packet;

    uint8_t payload_buffer[sizeof( struct netcode_connection_payload_packet_t ) + NETCODE_MAX_PAYLOAD_BYTES];
    struct netcode_connection_payload_packet_t * payload_packet = (struct netcode_connection_payload_packet_t*) payload_buffer;

    void * packet = NULL;

    switch ( packet_type )
    {
        case NETCODE_CONNECTION_REQUEST_PACKET:
        {
            // encrypt a connect token with the real private key so the read side can
            // fully decrypt and accept the request

            uint64_t expire_timestamp = fuzz_read_u64( in );
            if ( expire_timestamp == 0 )
                expire_timestamp = 1;

            uint8_t nonce[NETCODE_CONNECT_TOKEN_NONCE_BYTES];
            fuzz_read_bytes( in, nonce, sizeof( nonce ) );

            uint8_t token_data[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
            fuzz_read_bytes( in, token_data, sizeof( token_data ) - NETCODE_MAC_BYTES );
            memset( token_data + NETCODE_CONNECT_TOKEN_PRIVATE_BYTES - NETCODE_MAC_BYTES, 0, NETCODE_MAC_BYTES );

            if ( netcode_encrypt_connect_token_private( token_data,
                                                        NETCODE_CONNECT_TOKEN_PRIVATE_BYTES,
                                                        NETCODE_VERSION_INFO,
                                                        FUZZ_PROTOCOL_ID,
                                                        expire_timestamp,
                                                        nonce,
                                                        private_key ) != NETCODE_OK )
            {
                return;
            }

            request_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
            memcpy( request_packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            request_packet.protocol_id = FUZZ_PROTOCOL_ID;
            request_packet.connect_token_expire_timestamp = expire_timestamp;
            memcpy( request_packet.connect_token_nonce, nonce, NETCODE_CONNECT_TOKEN_NONCE_BYTES );
            memcpy( request_packet.connect_token_data, token_data, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

            packet = &request_packet;
        }
        break;

        case NETCODE_CONNECTION_DENIED_PACKET:
        {
            denied_packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;
            packet = &denied_packet;
        }
        break;

        case NETCODE_CONNECTION_CHALLENGE_PACKET:
        {
            challenge_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
            challenge_packet.challenge_token_sequence = fuzz_read_u64( in );
            fuzz_read_bytes( in, challenge_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            packet = &challenge_packet;
        }
        break;

        case NETCODE_CONNECTION_RESPONSE_PACKET:
        {
            response_packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
            response_packet.challenge_token_sequence = fuzz_read_u64( in );
            fuzz_read_bytes( in, response_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
            packet = &response_packet;
        }
        break;

        case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
        {
            keep_alive_packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
            keep_alive_packet.client_index = (int) fuzz_read_u16( in );
            keep_alive_packet.max_clients = (int) fuzz_read_u16( in );
            packet = &keep_alive_packet;
        }
        break;

        case NETCODE_CONNECTION_PAYLOAD_PACKET:
        {
            int payload_bytes = 1 + ( fuzz_read_u16( in ) % NETCODE_MAX_PAYLOAD_BYTES );
            payload_packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
            payload_packet->payload_bytes = payload_bytes;
            fuzz_read_bytes( in, payload_packet->payload_data, payload_bytes );
            packet = payload_packet;
        }
        break;

        case NETCODE_CONNECTION_DISCONNECT_PACKET:
        {
            disconnect_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
            packet = &disconnect_packet;
        }
        break;
    }

    uint8_t buffer[NETCODE_MAX_PACKET_BYTES];

    int written = netcode_write_packet( packet, buffer, NETCODE_MAX_PACKET_BYTES, sequence, packet_key, FUZZ_PROTOCOL_ID );

    FUZZ_CHECK( written > 0 );
    FUZZ_CHECK( written <= NETCODE_MAX_PACKET_BYTES );

    if ( corrupt )
    {
        buffer[corrupt_offset % written] ^= corrupt_xor;
    }

    struct netcode_replay_protection_t replay_protection;
    netcode_replay_protection_reset( &replay_protection );

    uint64_t read_sequence;
    void * read = fuzz_call_read_packet( buffer, written, &read_sequence, &replay_protection );

    if ( !corrupt || corrupt_xor == 0 )
    {
        // an uncorrupted packet written by netcode_write_packet must read back
        // with the same type and sequence

        FUZZ_CHECK( read );
        FUZZ_CHECK( ( (uint8_t*) read )[0] == packet_type );
        if ( packet_type != NETCODE_CONNECTION_REQUEST_PACKET )
        {
            FUZZ_CHECK( read_sequence == sequence );
        }
    }

    if ( read )
        free( read );
}

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    fuzz_initialize();

    struct fuzz_input_t in;
    in.data = data;
    in.size = size;
    in.offset = 0;

    if ( size < 1 )
        return 0;

    if ( fuzz_read_u8( &in ) & 1 )
    {
        fuzz_round_trip_packet( &in );
    }
    else
    {
        fuzz_raw_packet( &in );
    }

    return 0;
}
