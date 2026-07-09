/*
    fuzz the connect token readers.

    the public connect token is read by the client from whatever the game's backend
    returned, and the private connect token is read by the server after decrypting
    the portion of a connection request packet that was encrypted with the private
    key. both are parsers over untrusted bytes.

    mode 0: raw fuzz netcode_read_connect_token (public token, exact size required).
    mode 1: raw fuzz netcode_read_connect_token_private (post-decrypt private data).
    mode 2: round trip: build a valid private token from fuzz-derived fields, write
            it, read it back, and check the fields survive.
*/

#include "netcode.c"
#include "fuzz.h"

static int initialized = 0;

static void fuzz_initialize()
{
    if ( initialized )
        return;
    netcode_init();
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );
    initialized = 1;
}

static void fuzz_read_public_token( struct fuzz_input_t * in )
{
    uint8_t buffer[NETCODE_CONNECT_TOKEN_BYTES];
    memset( buffer, 0, sizeof( buffer ) );
    fuzz_read_bytes( in, buffer, sizeof( buffer ) );

    struct netcode_connect_token_t connect_token;
    netcode_read_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, &connect_token );
}

static void fuzz_read_private_token( struct fuzz_input_t * in )
{
    uint8_t buffer[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    memset( buffer, 0, sizeof( buffer ) );
    fuzz_read_bytes( in, buffer, sizeof( buffer ) );

    struct netcode_connect_token_private_t connect_token_private;
    netcode_read_connect_token_private( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &connect_token_private );
}

static void fuzz_round_trip_private_token( struct fuzz_input_t * in )
{
    struct netcode_connect_token_private_t input_token;
    memset( &input_token, 0, sizeof( input_token ) );

    input_token.client_id = fuzz_read_u64( in );
    input_token.timeout_seconds = (int) fuzz_read_u16( in );
    input_token.num_server_addresses = 1 + ( fuzz_read_u8( in ) % NETCODE_MAX_SERVERS_PER_CONNECT );

    int i;
    for ( i = 0; i < input_token.num_server_addresses; i++ )
    {
        struct netcode_address_t * address = &input_token.server_addresses[i];
        if ( fuzz_read_u8( in ) & 1 )
        {
            address->type = NETCODE_ADDRESS_IPV6;
            int j;
            for ( j = 0; j < 8; j++ )
                address->data.ipv6[j] = fuzz_read_u16( in );
        }
        else
        {
            address->type = NETCODE_ADDRESS_IPV4;
            int j;
            for ( j = 0; j < 4; j++ )
                address->data.ipv4[j] = fuzz_read_u8( in );
        }
        address->port = fuzz_read_u16( in );
    }

    fuzz_read_bytes( in, input_token.client_to_server_key, NETCODE_KEY_BYTES );
    fuzz_read_bytes( in, input_token.server_to_client_key, NETCODE_KEY_BYTES );
    fuzz_read_bytes( in, input_token.user_data, NETCODE_USER_DATA_BYTES );

    uint8_t buffer[NETCODE_CONNECT_TOKEN_PRIVATE_BYTES];
    netcode_write_connect_token_private( &input_token, buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES );

    struct netcode_connect_token_private_t output_token;
    FUZZ_CHECK( netcode_read_connect_token_private( buffer, NETCODE_CONNECT_TOKEN_PRIVATE_BYTES, &output_token ) == NETCODE_OK );

    FUZZ_CHECK( output_token.client_id == input_token.client_id );
    FUZZ_CHECK( output_token.timeout_seconds == input_token.timeout_seconds );
    FUZZ_CHECK( output_token.num_server_addresses == input_token.num_server_addresses );
    for ( i = 0; i < input_token.num_server_addresses; i++ )
    {
        FUZZ_CHECK( netcode_address_equal( &output_token.server_addresses[i], &input_token.server_addresses[i] ) );
    }
    FUZZ_CHECK( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    FUZZ_CHECK( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
    FUZZ_CHECK( memcmp( output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES ) == 0 );
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

    switch ( fuzz_read_u8( &in ) % 3 )
    {
        case 0: fuzz_read_public_token( &in ); break;
        case 1: fuzz_read_private_token( &in ); break;
        case 2: fuzz_round_trip_private_token( &in ); break;
    }

    return 0;
}
