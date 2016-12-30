
#include <speednet.h>
#include <stdio.h>

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;
	speednet_init();
	printf( "hello speednet world\n" );
	speednet_term();
	return 0;
}
