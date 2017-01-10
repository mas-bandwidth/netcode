
#include <netcode.h>
#include <stdio.h>
#include <assert.h>

#define SERVER_PORT 40000

extern void netcode_run_tests();

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;

	netcode_init();

    netcode_run_tests();

    netcode_term();
	
    return 0;
}
