#include <netcode.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>

#if    defined(__386__) || defined(i386)    || defined(__i386__)  \
    || defined(__X86)   || defined(_M_IX86)                       \
    || defined(_M_X64)  || defined(__x86_64__)                    \
    || defined(alpha)   || defined(__alpha) || defined(__alpha__) \
    || defined(_M_ALPHA)                                          \
    || defined(ARM)     || defined(_ARM)    || defined(__arm__)   \
    || defined(WIN32)   || defined(_WIN32)  || defined(__WIN32__) \
    || defined(_WIN32_WCE) || defined(__NT__)                     \
    || defined(__MIPSEL__)
  #define NETCODE_LITTLE_ENDIAN 1
#else
  #define NETCODE_BIG_ENDIAN 1
#endif

#define NETCODE_PLATFORM_WINDOWS                    1
#define NETCODE_PLATFORM_MAC                        2
#define NETCODE_PLATFORM_UNIX                       3

#if defined(_WIN32)
#define NETCODE_PLATFORM NETCODE_PLATFORM_WINDOWS
#elif defined(__APPLE__)
#define NETCODE_PLATFORM NETCODE_PLATFORM_MAC
#else
#define NETCODE_PLATFORM NETCODE_PLATFORM_UNIX
#endif

#define NETCODE_MAX_SERVERS_PER_CONNECT 16
#define NETCODE_KEY_BYTES 32
#define NETCODE_MAC_BYTES 16
#define NETCODE_NONCE_BYTES 8
#define NETCODE_CONNECT_TOKEN_BYTES 1400
#define NETCODE_CHALLENGE_TOKEN_BYTES 256
#define NETCODE_VERSION_INFO_BYTES 13
#define NETCODE_USER_DATA_BYTES 512

#define NETCODE_VERSION_INFO ( (const uint8_t*) "NETCODE 1.00" )

// ----------------------------------------------------------------

#define NETCODE_ADDRESS_IPV4 0
#define NETCODE_ADDRESS_IPV6 1

struct netcode_address_t
{
    uint8_t type;
    union
    {
        uint8_t ipv4[4];
        uint16_t ipv6[8];
    } address;
    uint16_t port;
};

int netcode_address_is_equal( const struct netcode_address_t * a, const struct netcode_address_t * b )
{
    assert( a );
    assert( b );

    if ( a->type != b->type )
        return 0;

    if ( a->port != b->port )
        return 0;

    if ( a->type == NETCODE_ADDRESS_IPV4 )
    {
        int i;
        for ( i = 0; i < 4; ++i )
        {
            if ( a->address.ipv4[i] != b->address.ipv4[i] )
                return 0;
        }
    }
    else if ( a->type == NETCODE_ADDRESS_IPV6 )
    {
        int i;
        for ( i = 0; i < 8; ++i )
        {
            if ( a->address.ipv6[i] != b->address.ipv6[i] )
                return 0;
        }
    }
    else
    {
        return 0;
    }

    return 1;
}

// ----------------------------------------------------------------

void netcode_write_uint8( uint8_t ** p, uint8_t value )
{
    **p = value;
    ++(*p);
}

void netcode_write_uint16( uint8_t ** p, uint16_t value )
{
    (*p)[0] = value >> 8;
    (*p)[1] = value & 0xFF;
    *p += 2;
}

void netcode_write_uint32( uint8_t ** p, uint32_t value )
{
    (*p)[0] = value >> 24;
    (*p)[1] = ( value >> 16 ) & 0xFF;
    (*p)[2] = ( value >> 8  ) & 0xFF;
    (*p)[3] = value & 0xFF;
    *p += 4;
}

void netcode_write_uint64( uint8_t ** p, uint64_t value )
{
    (*p)[0] = value >> 56;
    (*p)[1] = ( value >> 48 ) & 0xFF;
    (*p)[2] = ( value >> 40 ) & 0xFF;
    (*p)[3] = ( value >> 32 ) & 0xFF;
    (*p)[4] = ( value >> 24 ) & 0xFF;
    (*p)[5] = ( value >> 16 ) & 0xFF;
    (*p)[6] = ( value >> 8  ) & 0xFF;
    (*p)[7] = value & 0xFF;
    *p += 8;
}

void netcode_write_bytes( uint8_t ** p, const uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; ++i )
    {
        netcode_write_uint8( p, byte_array[i] );
    }
}

uint8_t netcode_read_uint8( const uint8_t ** p )
{
    uint8_t value = **p;
    ++(*p);
    return value;
}

uint16_t netcode_read_uint16( const uint8_t ** p )
{
    uint16_t value;
    value  = ( ( (uint16_t)( (*p)[0] ) ) << 8 );
    value |= (*p)[1];
    *p += 2;
    return value;
}

uint32_t netcode_read_uint32( const uint8_t ** p )
{
    uint32_t value;
    value  = ( ( (uint32_t)( (*p)[0] ) ) << 24 );
    value |= ( ( (uint32_t)( (*p)[1] ) ) << 16 );
    value |= ( ( (uint32_t)( (*p)[2] ) ) << 8 );
    value |= (*p)[3];
    *p += 4;
    return value;
}

uint64_t netcode_read_uint64( const uint8_t ** p )
{
    uint64_t value;
    value  = ( ( (uint64_t)( (*p)[0] ) ) << 56 );
    value |= ( ( (uint64_t)( (*p)[1] ) ) << 48 );
    value |= ( ( (uint64_t)( (*p)[2] ) ) << 40 );
    value |= ( ( (uint64_t)( (*p)[3] ) ) << 32 );
    value |= ( ( (uint64_t)( (*p)[4] ) ) << 24 );
    value |= ( ( (uint64_t)( (*p)[5] ) ) << 16 );
    value |= ( ( (uint64_t)( (*p)[6] ) ) << 8  );
    value |= (*p)[7];
    *p += 8;
    return value;
}

void netcode_read_bytes( const uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; ++i )
    {
        byte_array[i] = netcode_read_uint8( p );
    }
}

// ----------------------------------------------------------------

#ifdef _MSC_VER
#define SODIUM_STATIC
#endif // #ifdef _MSC_VER

#include <sodium.h>

void netcode_generate_key( uint8_t * key )
{
    assert( key );
    randombytes_buf( key, NETCODE_KEY_BYTES );
}

void netcode_random_bytes( uint8_t * data, int bytes )
{
    assert( data );
    assert( bytes > 0 );
    randombytes_buf( data, bytes );
}

int netcode_encrypt( const uint8_t * message, int message_length, 
                     uint8_t * encrypted_message, int * encrypted_message_length, 
                     const uint8_t * nonce, 
                     const uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_secretbox_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_secretbox_MACBYTES );

    assert( message );
    assert( message_length > 0 );
    assert( encrypted_message );
    assert( encrypted_message_length );

    if ( crypto_secretbox_easy( encrypted_message, message, message_length, nonce, key ) != 0 )
        return 0;

    *encrypted_message_length = message_length + NETCODE_MAC_BYTES;

    return 1;
}

int netcode_decrypt( const uint8_t * encrypted_message, int encrypted_message_length, 
                     uint8_t * decrypted_message, int * decrypted_message_length, 
                     const uint8_t * nonce, 
                     const uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_secretbox_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_secretbox_MACBYTES );

    if ( crypto_secretbox_open_easy( decrypted_message, encrypted_message, encrypted_message_length, nonce, key ) != 0 )
        return 0;

    *decrypted_message_length = encrypted_message_length - NETCODE_MAC_BYTES;

    return 1;
}

int netcode_encrypt_aead( const uint8_t * message, uint64_t message_length, 
                          uint8_t * encrypted_message, uint64_t * encrypted_message_length,
                          const uint8_t * additional, uint64_t additional_length,
                          const uint8_t * nonce,
                          const uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_aead_chacha20poly1305_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_aead_chacha20poly1305_ABYTES );

    unsigned long long encrypted_length;

    int result = crypto_aead_chacha20poly1305_encrypt( encrypted_message, &encrypted_length,
                                                       message, (unsigned long long) message_length,
                                                       additional, (unsigned long long) additional_length,
                                                       NULL, nonce, key );

    *encrypted_message_length = (uint64_t) encrypted_length;

    return result == 0;
}

int netcode_decrypt_aead( const uint8_t * encrypted_message, uint64_t encrypted_message_length, 
                          uint8_t * decrypted_message, uint64_t * decrypted_message_length,
                          const uint8_t * additional, uint64_t additional_length,
                          const uint8_t * nonce,
                          const uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_aead_chacha20poly1305_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_aead_chacha20poly1305_ABYTES );

    unsigned long long decrypted_length;

    int result = crypto_aead_chacha20poly1305_decrypt( decrypted_message, &decrypted_length,
                                                       NULL,
                                                       encrypted_message, (unsigned long long) encrypted_message_length,
                                                       additional, (unsigned long long) additional_length,
                                                       nonce, key );

    *decrypted_message_length = (uint64_t) decrypted_length;

    return result == 0;
}

// ----------------------------------------------------------------

struct netcode_connect_token_t
{
    uint64_t client_id;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
};

void netcode_generate_connect_token( struct netcode_connect_token_t * connect_token, uint64_t client_id, int num_server_addresses, struct netcode_address_t * server_addresses, const uint8_t * user_data )
{
    assert( connect_token );
    assert( num_server_addresses > 0 );
    assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    assert( server_addresses );
    assert( user_data );

    connect_token->client_id = client_id;
    
    connect_token->num_server_addresses = num_server_addresses;
    
    int i;
    for ( i = 0; i < num_server_addresses; ++i )
    {
        memcpy( &connect_token->server_addresses[i], &server_addresses[i], sizeof( struct netcode_address_t ) );
    }

    netcode_generate_key( connect_token->client_to_server_key );
    netcode_generate_key( connect_token->server_to_client_key );

    memcpy( connect_token->user_data, user_data, NETCODE_USER_DATA_BYTES );
}

void netcode_write_connect_token( const struct netcode_connect_token_t * connect_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

	assert( connect_token );
    assert( connect_token->num_server_addresses > 0 );
    assert( connect_token->num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
	assert( buffer );
    assert( buffer_length >= NETCODE_CONNECT_TOKEN_BYTES );

    memset( buffer, 0, NETCODE_CONNECT_TOKEN_BYTES );

    uint8_t * start = buffer;

    netcode_write_uint64( &buffer, connect_token->client_id );

    netcode_write_uint32( &buffer, connect_token->num_server_addresses );

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV4 );
            for ( j = 0; j < 4; ++j )
            {
                netcode_write_uint8( &buffer, connect_token->server_addresses[i].address.ipv4[j] );
            }
            netcode_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV6 );
            for ( j = 0; j < 8; ++j )
            {
                netcode_write_uint16( &buffer, connect_token->server_addresses[i].address.ipv6[j] );
            }
            netcode_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else
        {
            assert( 0 );
        }
    }

    netcode_write_bytes( &buffer, connect_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, connect_token->server_to_client_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, connect_token->user_data, NETCODE_USER_DATA_BYTES );

    assert( buffer - start <= NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

#if SODIUM_LIBRARY_VERSION_MAJOR > 7 || ( SODIUM_LIBRARY_VERSION_MAJOR && SODIUM_LIBRARY_VERSION_MINOR >= 3 )
#define SODIUM_SUPPORTS_OVERLAPPING_BUFFERS 1
#endif

int netcode_encrypt_connect_token( uint8_t * buffer, int buffer_length, const uint8_t * version_info, uint64_t protocol_id, uint64_t expire_timestamp, uint64_t sequence, const uint8_t * key )
{
    assert( buffer );
    assert( buffer_length == NETCODE_CONNECT_TOKEN_BYTES );
    assert( key );

    uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
		netcode_write_bytes( &p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &p, protocol_id );
        netcode_write_uint64( &p, expire_timestamp );
    }

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

    uint64_t encrypted_length;

    #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        if ( !netcode_encrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES, buffer, &encrypted_length, additional_data, sizeof( additional_data ), nonce, key ) )
            return 0;

    #else // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        uint8_t temp[NETCODE_CONNECT_TOKEN_BYTES];

        if ( !netcode_encrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES, temp, &encrypted_length, additional_data, sizeof( additional_data ), nonce, key ) )
            return 0;        

        memcpy( buffer, temp, NETCODE_CONNECT_TOKEN_BYTES );

    #endif // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

    assert( encrypted_length == NETCODE_CONNECT_TOKEN_BYTES );

    return 1;
}

int netcode_decrypt_connect_token( uint8_t * buffer, int buffer_length, const uint8_t * version_info, uint64_t protocol_id, uint64_t expire_timestamp, uint64_t sequence, const uint8_t * key )
{
	assert( buffer );
    assert( buffer_length == NETCODE_CONNECT_TOKEN_BYTES );
	assert( key );

    uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
		netcode_write_bytes( &p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &p, protocol_id );
        netcode_write_uint64( &p, expire_timestamp );
    }

    uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

    uint64_t decrypted_length;

    #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        if ( !netcode_decrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES, buffer, &decrypted_length, additional_data, sizeof( additional_data ), nonce, key ) )
            return 0;

    #else // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        uint8_t temp[NETCODE_CONNECT_TOKEN_BYTES];

        if ( !netcode_decrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES, temp, &decrypted_length, additional_data, sizeof( additional_data ), nonce, key ) )
            return 0;

        memcpy( buffer, temp, NETCODE_CONNECT_TOKEN_BYTES );

    #endif // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

    assert( decrypted_length == NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES );
	
	memset( buffer + NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES, 0, NETCODE_MAC_BYTES );

	return 1;
}

int netcode_read_connect_token( const uint8_t * buffer, int buffer_length, struct netcode_connect_token_t * connect_token )
{
    assert( buffer );
    assert( connect_token );

    if ( buffer_length < NETCODE_CONNECT_TOKEN_BYTES )
        return 0;
    
    connect_token->client_id = netcode_read_uint64( &buffer );

    connect_token->num_server_addresses = netcode_read_uint32( &buffer );

    if ( connect_token->num_server_addresses <= 0 )
        return 0;

    if ( connect_token->num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
        return 0;

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        connect_token->server_addresses[i].type = netcode_read_uint8( &buffer );

        if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            for ( j = 0; j < 4; ++j )
            {
                connect_token->server_addresses[i].address.ipv4[j] = netcode_read_uint8( &buffer );
            }
            connect_token->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            for ( j = 0; j < 8; ++j )
            {
                connect_token->server_addresses[i].address.ipv6[j] = netcode_read_uint16( &buffer );
            }
            connect_token->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else
        {
            return 0;
        }
    }

    netcode_read_bytes( &buffer, connect_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, connect_token->server_to_client_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, connect_token->user_data, NETCODE_USER_DATA_BYTES );

    return 1;
}

// -----------------------------------------------

struct netcode_challenge_token_t
{
    uint64_t client_id;
    uint8_t connect_token_mac[NETCODE_MAC_BYTES];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
};

void netcode_write_challenge_token( const struct netcode_challenge_token_t * challenge_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    assert( challenge_token );
    assert( buffer );
    assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    memset( buffer, 0, NETCODE_CHALLENGE_TOKEN_BYTES );

    uint8_t * start = buffer;

    netcode_write_uint64( &buffer, challenge_token->client_id );

    netcode_write_bytes( &buffer, challenge_token->connect_token_mac, NETCODE_MAC_BYTES );

    netcode_write_bytes( &buffer, challenge_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, challenge_token->server_to_client_key, NETCODE_KEY_BYTES );

    assert( buffer - start <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

int netcode_encrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, const uint8_t * key )
{
	assert( buffer );
	assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
	assert( key );

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

	int encrypted_bytes = 0;

	if ( !netcode_encrypt( buffer, NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, buffer, &encrypted_bytes, nonce, key ) )
		return 0;

	assert( encrypted_bytes == NETCODE_CHALLENGE_TOKEN_BYTES );

	return 1;
}

int netcode_decrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, const uint8_t * key )
{
	assert( buffer );
	assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
	assert( key );

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

	int decrypted_bytes = 0;

	if ( !netcode_decrypt( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, buffer, &decrypted_bytes, nonce, key ) )
		return 0;

	assert( decrypted_bytes == NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );

	return 1;
}

int netcode_read_challenge_token( const uint8_t * buffer, int buffer_length, struct netcode_challenge_token_t * challenge_token )
{
    assert( buffer );
    assert( challenge_token );

    if ( buffer_length < NETCODE_CHALLENGE_TOKEN_BYTES )
        return 0;

	const uint8_t * start = buffer;
    
    challenge_token->client_id = netcode_read_uint64( &buffer );

    netcode_read_bytes( &buffer, challenge_token->connect_token_mac, NETCODE_MAC_BYTES );

	netcode_read_bytes( &buffer, challenge_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, challenge_token->server_to_client_key, NETCODE_KEY_BYTES );

	assert( buffer - start == 8 + NETCODE_MAC_BYTES + NETCODE_KEY_BYTES + NETCODE_KEY_BYTES );

    return 1;
}

// ----------------------------------------------------------------

#define NETCODE_CONNECTION_REQUEST_PACKET           0
#define NETCODE_CONNECTION_DENIED_PACKET            1
#define NETCODE_CONNECTION_CHALLENGE_PACKET         2
#define NETCODE_CONNECTION_RESPONSE_PACKET          3
#define NETCODE_CONNECTION_CONFIRM_PACKET           4
#define NETCODE_CONNECTION_KEEP_ALIVE_PACKET        5
#define NETCODE_CONNECTION_PAYLOAD_PACKET           6
#define NETCODE_CONNECTION_DISCONNECT_PACKET        7

struct netcode_connection_request_packet_t
{
    uint8_t packet_type;
    uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
    uint64_t protocol_id;
    uint64_t connect_token_expire_timestamp;
    uint64_t connect_token_sequence;
    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];
};

struct netcode_connection_denied_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_challenge_packet_t
{
    uint8_t packet_type;
    uint8_t challenge_token_nonce[NETCODE_NONCE_BYTES];
    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
};

struct netcode_connection_response_packet_t
{
    uint8_t packet_type;
    uint8_t challenge_token_nonce[NETCODE_NONCE_BYTES];
    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
};

struct netcode_connection_confirm_packet_t
{
    uint8_t packet_type;
    uint32_t client_index;
};

struct netcode_connection_keep_alive_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_payload_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_disconnect_packet_t
{
    uint8_t packet_type;
};

struct netcode_packet_context_t
{
    uint64_t protocol_id;
    uint64_t current_timestamp;
	uint8_t connect_token_key[NETCODE_KEY_BYTES];
};

int netcode_write_packet( void * packet, uint8_t * buffer, int buffer_length, struct netcode_packet_context_t * context )
{
    (void) context;

    uint8_t packet_type = ((uint8_t*)packet)[0];

    if ( packet_type == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet

        assert( buffer_length >= 1 + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES );

        struct netcode_connection_request_packet_t * p = (struct netcode_connection_request_packet_t*) packet;

        uint8_t * start = buffer;

        netcode_write_uint8( &buffer, NETCODE_CONNECTION_REQUEST_PACKET );
		netcode_write_bytes( &buffer, p->version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &buffer, p->protocol_id );
        netcode_write_uint64( &buffer, p->connect_token_expire_timestamp );
        netcode_write_uint64( &buffer, p->connect_token_sequence );
        netcode_write_bytes( &buffer, p->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 1 + 13 + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES );

        return (int) ( buffer - start );
    }
    else
    {
        // encrypted packets

        // ...
    }

    return 0;
}

void * netcode_read_packet( uint8_t * buffer, int buffer_length, struct netcode_packet_context_t * context )
{
    assert( context );

    const uint8_t * start = buffer;

    uint8_t packet_type = netcode_read_uint8( &buffer );

    if ( packet_type == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet

        if ( buffer_length != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES )
            return NULL;

		uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
		netcode_read_bytes( &buffer, version_info, NETCODE_VERSION_INFO_BYTES );
		if ( version_info[0]  != 'N' || 
			 version_info[1]  != 'E' || 
			 version_info[2]  != 'T' || 
			 version_info[3]  != 'C' || 
			 version_info[4]  != 'O' ||
			 version_info[5]  != 'D' ||
			 version_info[6]  != 'E' ||
			 version_info[7]  != ' ' || 
			 version_info[8]  != '1' ||
			 version_info[9]  != '.' ||
			 version_info[10] != '0' ||
			 version_info[11] != '0' ||
			 version_info[12] != '\0' )
		{
			return NULL;
		}

        uint64_t packet_protocol_id = netcode_read_uint64( &buffer );
        if ( packet_protocol_id != context->protocol_id )
            return NULL;

        uint64_t packet_connect_token_expire_timestamp = netcode_read_uint64( &buffer );
        if ( packet_connect_token_expire_timestamp <= context->current_timestamp )
            return NULL;

		uint64_t packet_connect_token_sequence = netcode_read_uint64( &buffer );

		assert( buffer - start == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_NONCE_BYTES );

		if ( !netcode_decrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, version_info, context->protocol_id, packet_connect_token_expire_timestamp, packet_connect_token_sequence, context->connect_token_key ) )
			return NULL;

        struct netcode_connection_request_packet_t * packet = (struct netcode_connection_request_packet_t*) malloc( sizeof( struct netcode_connection_request_packet_t ) );

        if ( !packet )
            return NULL;

        packet->packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
		memcpy( packet->version_info, version_info, NETCODE_VERSION_INFO_BYTES );
        packet->protocol_id = packet_protocol_id;
        packet->connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
		packet->connect_token_sequence = packet_connect_token_sequence;
        netcode_read_bytes( &buffer, packet->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES );

        return packet;
    }
    else
    {
        // encrypted packets

        // ...
    }

    return NULL;
}

// ----------------------------------------------------------------

struct netcode_t
{
    int initialized;
};

static struct netcode_t netcode;

int netcode_init()
{
    assert( !netcode.initialized );

    // ...

    netcode.initialized = 1;

	return 0;
}

void netcode_term()
{
	assert( netcode.initialized );

    // ...

    netcode.initialized = 0;
}

// ----------------------------------------------------------------

struct netcode_client_t
{
	int dummy;
};

struct netcode_client_t * netcode_client_create()
{
    assert( netcode.initialized );

	struct netcode_client_t * client = (struct netcode_client_t*) malloc( sizeof( struct netcode_client_t ) );

    if ( !client )
        return NULL;

	// ...

	return client;
}

void netcode_client_update( struct netcode_client_t * client, double time )
{
    assert( client );

	(void) client;
	(void) time;
	
	// ...
}

int netcode_client_get_client_index( struct netcode_client_t * client )
{
    assert( client );

	(void) client;

	// ...

	return -1;
}

void netcode_client_connect( struct netcode_client_t * client, const char * token )
{
    assert( client );
    assert( token );

	(void) client;
	(void) token;

	// ...
}

void netcode_client_send_packet_to_server( struct netcode_client_t * client, const uint8_t * packet_data, int packet_size )
{
    assert( client );
    assert( packet_data );
    assert( packet_size );

	(void) client;
	(void) packet_data;
	(void) packet_size;

	// ...
}

int netcode_client_receive_packet_from_server( struct netcode_client_t * client, uint8_t * buffer, int buffer_length )
{
    assert( client );
    assert( buffer );
    assert( buffer_length > 0 );

	(void) client;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void netcode_client_disconnect( struct netcode_client_t * client )
{
    assert( client );

	(void) client;

	// ...
}

void netcode_client_destroy( struct netcode_client_t * client )
{
    assert( client );

    // ...

	free( client );
}

// ----------------------------------------------------------------

struct netcode_server_t
{
	int dummy;
};

struct netcode_server_t * netcode_server_create( uint16_t port )
{
	(void) port;

    assert( netcode.initialized );

    struct netcode_server_t * server = (struct netcode_server_t*) malloc( sizeof( struct netcode_server_t ) );

    if ( !server )
        return NULL;

    // ...

    return server;
}

void netcode_server_start( struct netcode_server_t * server, int max_clients )
{
	(void) server;
	(void) max_clients;

	// ...
}

void netcode_server_update( struct netcode_server_t * server, double time )
{
	(void) server;
	(void) time;

	// ...
}

int netcode_server_is_client_connected( struct netcode_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...

	return 0;
}

int netcode_server_receive_packet_from_client( struct netcode_server_t * server, int client_index, uint8_t * buffer, int buffer_length )
{
	(void) server;
	(void) client_index;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void netcode_server_send_packet_to_client( struct netcode_server_t * server, int client_index, const uint8_t * packet_data, int packet_size )
{
	(void) server;
	(void) client_index;
	(void) packet_data;
	(void) packet_size;

	// ...
}

void netcode_server_disconnect_client( struct netcode_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...
}

void netcode_server_disconnect_all_clients( struct netcode_server_t * server )
{
	(void) server;

	// ...
}

void netcode_server_stop( struct netcode_server_t * server )
{
	(void) server;

	// ...
}

void netcode_server_destroy( struct netcode_server_t * server )
{
    assert( server );

	(void) server;

	// ...

    free( server );
}

// ---------------------------------------------------------------

#define NETCODE_TEST 1

#if NETCODE_TEST

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

static void check_handler( const char * condition, 
                           const char * function,
                           const char * file,
                           int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
#ifndef NDEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

#define check( condition )                                                     \
do                                                                             \
{                                                                              \
    if ( !(condition) )                                                        \
    {                                                                          \
        check_handler( #condition, __FUNCTION__, __FILE__, __LINE__ );         \
    }                                                                          \
} while(0)

static void test_endian()
{
    uint32_t value = 0x11223344;

    const char * bytes = (const char*) &value;

#if NETCODE_LITTLE_ENDIAN

    check( bytes[0] == 0x44 );
    check( bytes[1] == 0x33 );
    check( bytes[2] == 0x22 );
    check( bytes[3] == 0x11 );

#else // #if NETCODE_LITTLE_ENDIAN

    check( bytes[3] == 0x44 );
    check( bytes[2] == 0x33 );
    check( bytes[1] == 0x22 );
    check( bytes[0] == 0x11 );

#endif // #if NETCODE_LITTLE_ENDIAN
}

#define TEST_PROTOCOL_ID    0x1122334455667788LL
#define TEST_CLIENT_ID      0x1LL
#define TEST_SERVER_PORT    40000

static void test_connect_token()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.address.ipv4[0] = 127;
    server_address.address.ipv4[1] = 0;
    server_address.address.ipv4[2] = 0;
    server_address.address.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t input_token;

    netcode_generate_connect_token( &input_token, TEST_CLIENT_ID, 1, &server_address, user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( memcmp( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) == 0 );
    check( netcode_address_is_equal( &input_token.server_addresses[0], &server_address ) );

    // write it to a buffer

    uint8_t buffer[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &input_token, buffer, NETCODE_CONNECT_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 0;
    uint64_t expire_timestamp = time( NULL ) + 30;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key( key );    

    check( netcode_encrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // decrypt the buffer

    check( netcode_decrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // read the connect token back in

    struct netcode_connect_token_t output_token;

    check( netcode_read_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, &output_token ) == 1 );

	// make sure that everything matches the original connect token

    check( output_token.client_id == input_token.client_id );
    check( output_token.num_server_addresses == input_token.num_server_addresses );
    check( netcode_address_is_equal( &output_token.server_addresses[0], &input_token.server_addresses[0] ) );
    check( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES ) == 0 );
}

static void test_challenge_token()
{
    // generate a challenge token

    struct netcode_challenge_token_t input_token;

    input_token.client_id = TEST_CLIENT_ID;
	netcode_random_bytes( input_token.connect_token_mac, NETCODE_MAC_BYTES );
	netcode_generate_key( input_token.client_to_server_key );
	netcode_generate_key( input_token.server_to_client_key );

    // write it to a buffer

    uint8_t buffer[NETCODE_CHALLENGE_TOKEN_BYTES];

    netcode_write_challenge_token( &input_token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

	/*
    // encrypt the buffer

    uint64_t sequence = 0;
    uint64_t expire_timestamp = time( NULL ) + 30;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key( key );    

    check( netcode_encrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // decrypt the buffer

    check( netcode_decrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );
	*/

    // read the challenge token back in

    struct netcode_challenge_token_t output_token;

    check( netcode_read_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, &output_token ) == 1 );

	// make sure that everything matches the original connect token

    check( output_token.client_id == input_token.client_id );
    check( memcmp( output_token.connect_token_mac, input_token.connect_token_mac, NETCODE_MAC_BYTES ) == 0 );
    check( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
}

static void test_connection_request_packet()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.address.ipv4[0] = 127;
    server_address.address.ipv4[1] = 0;
    server_address.address.ipv4[2] = 0;
    server_address.address.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t input_token;

    netcode_generate_connect_token( &input_token, TEST_CLIENT_ID, 1, &server_address, user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( memcmp( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) == 0 );
    check( netcode_address_is_equal( &input_token.server_addresses[0], &server_address ) );

    // write the conect token to a buffer (non-encrypted)

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &input_token, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    uint8_t encrypted_connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    memcpy( encrypted_connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    uint64_t connect_token_sequence = 0;
    uint64_t connect_token_expire_timestamp = time( NULL ) + 30;
    uint8_t connect_token_key[NETCODE_KEY_BYTES];
    netcode_generate_key( connect_token_key );

    check( netcode_encrypt_connect_token( encrypted_connect_token_data, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, connect_token_expire_timestamp, connect_token_sequence, connect_token_key ) == 1 );

    // setup a connection request packet wrapping the encrypted connect token

    struct netcode_connection_request_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    memcpy( input_packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    input_packet.connect_token_sequence = connect_token_sequence;
    memcpy( input_packet.connect_token_data, encrypted_connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

	// write the connection request packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
	context.protocol_id = TEST_PROTOCOL_ID;
	context.current_timestamp = (uint64_t) time( NULL );
	memcpy( context.connect_token_key, connect_token_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), &context );

    check( bytes_written > 0 );

	// read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

    struct netcode_connection_request_packet_t * output_packet = (struct netcode_connection_request_packet_t*) netcode_read_packet( buffer, bytes_written, &context );

    check( output_packet );

	// make sure the packet data read matches what was written
	
    check( output_packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
    check( memcmp( output_packet->version_info, input_packet.version_info, NETCODE_VERSION_INFO_BYTES ) == 0 );
    check( output_packet->protocol_id == input_packet.protocol_id );
    check( output_packet->connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
	check( output_packet->connect_token_sequence == input_packet.connect_token_sequence );
    check( memcmp( output_packet->connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES ) == 0 );

    free( output_packet );
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        printf( #test_function "\n" );                                      \
        test_function();                                                    \
    }                                                                       \
    while (0)

void netcode_test()
{
    RUN_TEST( test_endian );
    RUN_TEST( test_connect_token );
    RUN_TEST( test_challenge_token );
    RUN_TEST( test_connection_request_packet );
}

#endif // #if NETCODE_TEST
