#include <speednet.h>
#include <stdlib.h>

#if    defined(__386__) || defined(i386)    || defined(__i386__)  \
    || defined(__X86)   || defined(_M_IX86)                       \
    || defined(_M_X64)  || defined(__x86_64__)                    \
    || defined(alpha)   || defined(__alpha) || defined(__alpha__) \
    || defined(_M_ALPHA)                                          \
    || defined(ARM)     || defined(_ARM)    || defined(__arm__)   \
    || defined(WIN32)   || defined(_WIN32)  || defined(__WIN32__) \
    || defined(_WIN32_WCE) || defined(__NT__)                     \
    || defined(__MIPSEL__)
  #define SPEEDNET_LITTLE_ENDIAN 1
#else
  #define SPEEDNET_BIG_ENDIAN 1
#endif

#define SPEEDNET_PLATFORM_WINDOWS                    1
#define SPEEDNET_PLATFORM_MAC                        2
#define SPEEDNET_PLATFORM_UNIX                       3

#if defined(_WIN32)
#define SPEEDNET_PLATFORM SPEEDNET_PLATFORM_WINDOWS
#elif defined(__APPLE__)
#define SPEEDNET_PLATFORM SPEEDNET_PLATFORM_MAC
#else
#define SPEEDNET_PLATFORM SPEEDNET_PLATFORM_UNIX
#endif

#define SPEEDNET_MAX_SERVERS_PER_CONNECT 8
#define SPEEDNET_KEY_BYTES 32
#define SPEEDNET_MAC_BYTES 16

struct speednet_address_t
{
	// todo
	int dummy;
};

struct speednet_connect_token_t
{
    uint64_t protocol_id;
    uint64_t client_id;
    uint64_t expire_timestamp;
    int num_server_addresses;
    struct speednet_address_t server_addresses[SPEEDNET_MAX_SERVERS_PER_CONNECT];
    uint8_t clientToServerKey[SPEEDNET_KEY_BYTES];
    uint8_t serverToClientKey[SPEEDNET_KEY_BYTES];
};

int speednet_init()
{
	return 0;
}

void speednet_term()
{
	// ...
}

struct speednet_client_t
{
	int dummy;
};

struct speednet_client_t * speednet_client_create()
{
	struct speednet_client_t * client = (struct speednet_client_t*) malloc( sizeof( struct speednet_client_t ) );

	// ...

	return client;
}

void speednet_client_update( struct speednet_client_t * client, double time )
{
	(void) client;
	(void) time;
	
	// ...
}

int speednet_client_get_client_index( struct speednet_client_t * client )
{
	(void) client;

	// ...

	return -1;
}

void speednet_client_connect( struct speednet_client_t * client, const char * token )
{
	(void) client;
	(void) token;

	// ...
}

void speednet_client_send_packet_to_server( struct speednet_client_t * client, const uint8_t * packet_data, int packet_size )
{
	(void) client;
	(void) packet_data;
	(void) packet_size;

	// ...
}

int speednet_client_receive_packet_from_server( struct speednet_client_t * client, uint8_t * buffer, int buffer_length )
{
	(void) client;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void speednet_client_disconnect( struct speednet_client_t * client )
{
	(void) client;

	// ...
}

void speednet_client_destroy( struct speednet_client_t * client )
{
	(void) client;

	// todo: destroy it
}

struct speednet_server_t
{
	int dummy;
};

struct speednet_server_t * speednet_server_create( uint16_t port )
{
	(void) port;

	// todo

	return NULL;
}

void speednet_server_start( struct speednet_server_t * server, int max_clients )
{
	(void) server;
	(void) max_clients;

	// ...
}

void speednet_server_update( struct speednet_server_t * server, double time )
{
	(void) server;
	(void) time;

	// ...
}

int speednet_server_is_client_connected( struct speednet_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...

	return 0;
}

int speednet_server_receive_packet_from_client( struct speednet_server_t * server, int client_index, uint8_t * buffer, int buffer_length )
{
	(void) server;
	(void) client_index;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void speednet_server_send_packet_to_client( struct speednet_server_t * server, int client_index, const uint8_t * packet_data, int packet_size )
{
	(void) server;
	(void) client_index;
	(void) packet_data;
	(void) packet_size;

	// ...
}

void speednet_server_disconnect_client( struct speednet_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...
}

void speednet_server_disconnect_all_clients( struct speednet_server_t * server )
{
	(void) server;

	// ...
}

void speednet_server_stop( struct speednet_server_t * server )
{
	(void) server;

	// ...
}

void speednet_server_destroy( struct speednet_server_t * server )
{
	(void) server;

	// todo: destroy
}
