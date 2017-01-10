
#include <netcode.h>
#include <stdio.h>
#include <assert.h>

#define SERVER_PORT 40000

extern void netcode_test();

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;

	netcode_init();

    netcode_test();

    netcode_term();
	
    return 0;
}
