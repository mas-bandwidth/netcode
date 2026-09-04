#include <netcode.h>
#include <stdio.h>

int main()
{
    if ( netcode_init() != NETCODE_OK )
    {
        printf( "error: netcode_init failed\n" );
        return 1;
    }

    netcode_term();

    printf( "netcode %s installed and linked\n", NETCODE_VERSION_FULL );

    return 0;
}
