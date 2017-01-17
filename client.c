/*
    netcode.io reference implementation

    Copyright © 2016, The Network Protocol Company, Inc.

    Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

        1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

        2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer 
           in the documentation and/or other materials provided with the distribution.

        3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived 
           from this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
    SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
    USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <netcode.h>
#include <stdio.h>
#include <assert.h>

extern void netcode_test();

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;

	netcode_init();

    double time = 0.0f;
	double delta_time = 0.1f;

	printf( "[client]\n" );

    struct netcode_client_t * client = netcode_client_create( time );

    if ( !client )
    {
        printf( "error: failed to create client\n" );
        return 1;
    }

    netcode_client_connect( client, (uint8_t*) "connect data" );

	for ( int i = 0; i < 10; ++i )
	{
		printf( "%d: ...\n", i );

		netcode_client_receive_packets( client );

		netcode_client_send_packets( client );

        // todo: if client is in error state break

		// todo: sleep

		time += delta_time;

		netcode_client_advance_time( client, time );
	}

    netcode_client_destroy( client );

    netcode_term();
	
    return 0;
}
