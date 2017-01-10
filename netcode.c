#include <netcode.h>
#include <stdlib.h>
#include <assert.h>

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

#define NETCODE_MAX_SERVERS_PER_CONNECT 8
#define NETCODE_KEY_BYTES 32
#define NETCODE_MAC_BYTES 16
#define NETCODE_NONCE_BYTES 8
#define NETCODE_CONNECT_TOKEN_BYTES 1024
#define NETCODE_CHALLENGE_TOKEN_BYTES 256

// ----------------------------------------------------------------

struct netcode_address_t
{
    int dummy;
};

struct netcode_connect_token_t
{
    uint64_t client_id;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
};

struct netcode_challenge_token_t
{
    uint64_t client_id;
    uint8_t connect_token_mac[NETCODE_MAC_BYTES];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
};

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
    uint64_t protocol_id;                                               // todo: use both as additional data and convert to little endian before using as additional data
    uint64_t connect_token_expire_timestamp;
    uint8_t connect_token_nonce[NETCODE_NONCE_BYTES];
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

void netcode_write_bytes( uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    for ( int i = 0; i < num_bytes; ++i )
    {
        netcode_write_uint8( p, byte_array[i] );
    }
}

struct netcode_packet_context_t
{
    uint64_t protocol_id;
    uint64_t current_timestamp;
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
        netcode_write_uint64( &buffer, p->protocol_id );
        netcode_write_uint64( &buffer, p->connect_token_expire_timestamp );
        netcode_write_bytes( &buffer, p->connect_token_nonce, NETCODE_NONCE_BYTES );
        netcode_write_bytes( &buffer, p->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 1 + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES );

        return (int) ( buffer - start );
    }
    else
    {
        // encrypted packets

        // ...
    }

    return 0;
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
    for ( int i = 0; i < num_bytes; ++i )
    {
        byte_array[i] = netcode_read_uint8( p );
    }
}

void * netcode_read_packet( const uint8_t * buffer, int buffer_length, struct netcode_packet_context_t * context )
{
    assert( context );

    uint8_t packet_type = buffer[0];

    if ( packet_type == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet

        if ( buffer_length != 1 + 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES )
            return NULL;

		buffer++;

        const uint8_t * start = buffer;

        uint64_t packet_protocol_id = netcode_read_uint64( &buffer );

        if ( packet_protocol_id != context->protocol_id )
            return NULL;

        uint64_t packet_connect_token_expire_timestamp = netcode_read_uint64( &buffer );

        if ( packet_connect_token_expire_timestamp <= context->current_timestamp )
            return NULL;

        // todo: want to perform decryption of connect token here, in-place ideally (or to stack, if required depending on version of libsodium)

        struct netcode_connection_request_packet_t * packet = (struct netcode_connection_request_packet_t*) malloc( sizeof( struct netcode_connection_request_packet_t ) );

        if ( !packet )
            return NULL;

        packet->packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
        packet->protocol_id = packet_protocol_id;
        packet->connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
        netcode_read_bytes( &buffer, packet->connect_token_nonce, NETCODE_NONCE_BYTES );
        netcode_read_bytes( &buffer, packet->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 8 + 8 + NETCODE_NONCE_BYTES + NETCODE_CONNECT_TOKEN_BYTES );

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

// temporary: 
#define NETCODE_TESTS 1

#if NETCODE_TESTS

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

void test_endian()
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

#define TEST_PROTOCOL_ID 0x1122334455667788LL

void test_connection_request_packet()
{
    struct netcode_connection_request_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = (uint64_t) time( NULL );
    memset( input_packet.connect_token_nonce, 0, NETCODE_NONCE_BYTES );
    memset( input_packet.connect_token_data, 0, NETCODE_CONNECT_TOKEN_BYTES );

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
	context.protocol_id = TEST_PROTOCOL_ID;

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), &context );

    check( bytes_written > 0 );

    struct netcode_connection_request_packet_t * output_packet = (struct netcode_connection_request_packet_t*) netcode_read_packet( buffer, bytes_written, &context );

    check( output_packet );

    check( output_packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
    check( output_packet->protocol_id == input_packet.protocol_id );
    check( output_packet->connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
    check( memcmp( output_packet->connect_token_nonce, input_packet.connect_token_nonce, NETCODE_NONCE_BYTES ) == 0 );
    check( memcmp( output_packet->connect_token_data, input_packet.connect_token_data, NETCODE_CONNECT_TOKEN_BYTES ) == 0 );

    // todo: this should be replaced with a test if the connect token decrypted, once the decrypt is done in place on packet read

    free( output_packet );
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        printf( #test_function "\n" );                                      \
        test_function();                                                    \
    }                                                                       \
    while (0)

void netcode_run_tests()
{
    RUN_TEST( test_endian );
    RUN_TEST( test_connection_request_packet );
}

#endif // #if NETCODE_TESTS
