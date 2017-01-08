
#include <netcode.h>
#include <stdio.h>

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;
	netcode_init();
	printf( "hello netcode.io\n" );
	netcode_term();
	return 0;
}
