#include <netcode.h>
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

struct netcode_address_t
{
	// todo
	int dummy;
};

struct netcode_connect_token_t
{
    uint64_t protocol_id;
    uint64_t client_id;
    uint64_t expire_timestamp;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t clientToServerKey[NETCODE_KEY_BYTES];
    uint8_t serverToClientKey[NETCODE_KEY_BYTES];
};

int netcode_init()
{
	return 0;
}

void netcode_term()
{
	// ...
}

struct netcode_client_t
{
	int dummy;
};

struct netcode_client_t * netcode_client_create()
{
	struct netcode_client_t * client = (struct netcode_client_t*) malloc( sizeof( struct netcode_client_t ) );

	// ...

	return client;
}

void netcode_client_update( struct netcode_client_t * client, double time )
{
	(void) client;
	(void) time;
	
	// ...
}

int netcode_client_get_client_index( struct netcode_client_t * client )
{
	(void) client;

	// ...

	return -1;
}

void netcode_client_connect( struct netcode_client_t * client, const char * token )
{
	(void) client;
	(void) token;

	// ...
}

void netcode_client_send_packet_to_server( struct netcode_client_t * client, const uint8_t * packet_data, int packet_size )
{
	(void) client;
	(void) packet_data;
	(void) packet_size;

	// ...
}

int netcode_client_receive_packet_from_server( struct netcode_client_t * client, uint8_t * buffer, int buffer_length )
{
	(void) client;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void netcode_client_disconnect( struct netcode_client_t * client )
{
	(void) client;

	// ...
}

void netcode_client_destroy( struct netcode_client_t * client )
{
	(void) client;

	// todo: destroy it
}

struct netcode_server_t
{
	int dummy;
};

struct netcode_server_t * netcode_server_create( uint16_t port )
{
	(void) port;

	// todo

	return NULL;
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
	(void) server;

	// todo: destroy
}
