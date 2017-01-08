
#include <netcode.h>
#include <stdio.h>
#include <assert.h>

#define SERVER_PORT 40000

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;

	netcode_init();
	
    printf( "hello netcode.io\n" );
	
    struct netcode_client_t * client = netcode_client_create();

    struct netcode_server_t * server = netcode_server_create( SERVER_PORT );

    assert( client );
    
    assert( server );

    netcode_client_destroy( client );

    netcode_server_destroy( server );

    netcode_term();
	
    return 0;
}
