/*
    netcode.io reference implementation

    Copyright © 2017, The Network Protocol Company, Inc.

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
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <signal.h>
#include <inttypes.h>

#define MAX_SERVERS 64
#define MAX_CLIENTS 1024
#define SERVER_BASE_PORT 40000
#define CONNECT_TOKEN_EXPIRY 45
#define PROTOCOL_ID 0x1122334455667788

static volatile int quit = 0;

void interrupt_handler( int signal )
{
    (void) signal;
    quit = 1;
}

int random_int( int a, int b )
{
    assert( a < b );
    int result = a + rand() % ( b - a + 1 );
    assert( result >= a );
    assert( result <= b );
    return result;
}

float random_float( float a, float b )
{
    assert( a < b );
    float random = ( (float) rand() ) / (float) RAND_MAX;
    float diff = b - a;
    float r = random * diff;
    return a + r;
}

struct netcode_server_t * server[MAX_SERVERS];
struct netcode_client_t * client[MAX_CLIENTS];
uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
uint8_t private_key[NETCODE_KEY_BYTES];

void initialize()
{
    printf( "initializing\n" );

    netcode_init();

    netcode_log_level( NETCODE_LOG_LEVEL_INFO );

    memset( server, 0, sizeof( server ) );
    memset( client, 0, sizeof( client ) );

    netcode_random_bytes( private_key, NETCODE_KEY_BYTES );

    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; ++i )
    {
        packet_data[i] = (uint8_t) i;
    }
}

void shutdown()
{
    printf( "shutdown\n" );

    int i;

    for ( i = 0; i < MAX_SERVERS; ++i )
    {
        if ( server[i] != NULL )
        {
            netcode_server_destroy( server[i] );
            server[i] = NULL;
        }
    }

    for ( i = 0; i < MAX_CLIENTS; ++i )
    {
        if ( client[i] != NULL )
        {
            netcode_client_destroy( client[i] );
            client[i] = NULL;
        }
    }

    netcode_term();
}

void run_iteration( double time )
{
    int i;

    for ( i = 0; i < MAX_SERVERS; ++i )
    {
        if ( server[i] == NULL && random_int( 0, 10 ) == 0 )
        {
            char server_address[256];
            sprintf( server_address, "127.0.0.1:%d", SERVER_BASE_PORT + i );
            server[i] = netcode_server_create( server_address, PROTOCOL_ID, private_key, time );
            printf( "created server %p\n", server[i] );
        }

        if ( server[i] != NULL && netcode_server_num_connected_clients( server[i] ) == netcode_server_max_clients( server[i] ) && random_int( 0, 10000 ) == 0 )
        {
            printf( "destroy server %p\n", server[i] );
            netcode_server_destroy( server[i] );
            server[i] = NULL;
        }
    }

    for ( i = 0; i < MAX_CLIENTS; ++i )
    {
        if ( client[i] == NULL && random_int( 0, 10 ) == 0 )
        {
            client[i] = netcode_client_create( "0.0.0.0", time );
            printf( "created client %p\n", client[i] );
        }

        if ( client[i] != NULL && random_int( 0, 1000 ) == 0 )
        {
            printf( "destroy client %p\n", client[i] );
            netcode_client_destroy( client[i] );
            client[i] = NULL;
        }
    }

    for ( i = 0; i < MAX_SERVERS; ++i )
    {
        if ( server[i] != NULL )
        {
            if ( random_int( 0, 10 ) == 0 && !netcode_server_running( server[i] ) )
            {
                netcode_server_start( server[i], random_int( 1, NETCODE_MAX_CLIENTS ) );
            }

            if ( random_int( 0, 1000 ) == 0 && netcode_server_num_connected_clients( server[i] ) == netcode_server_max_clients( server[i] ) && netcode_server_running( server[i] ) )
            {
                netcode_server_stop( server[i] );
            }

            if ( netcode_server_running( server[i] ) )
            {
                int max_clients = netcode_server_max_clients( server[i] );
                int j;
                for ( j = 0; j < max_clients; ++j )
                {
                    if ( netcode_server_client_connected( server[i], j ) )
                    {
                        netcode_server_send_packet( server[i], 0, packet_data, NETCODE_MAX_PACKET_SIZE );
                    }
                }
            }

            netcode_server_update( server[i], time );
        }
        
    }

    for ( i = 0; i < MAX_CLIENTS; ++i )
    {
        if ( client[i] != NULL )
        {
            if ( random_int( 0, 10 ) == 0 && netcode_client_state( client[i] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                uint64_t client_id = 0;
                netcode_random_bytes( (uint8_t*) &client_id, 8 );

                uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

                int num_server_addresses = 0;
                char * server_address[NETCODE_MAX_SERVERS_PER_CONNECT];
                int j;
                for ( j = 0; j < MAX_SERVERS; ++j )
                {
                    if ( num_server_addresses == NETCODE_MAX_SERVERS_PER_CONNECT )
                        break;

                    if ( server[j] && netcode_server_running( server[j] ) )
                    {
                        server_address[num_server_addresses] = (char*) malloc( 256 ); 
                        sprintf( server_address[num_server_addresses], "127.0.0.1:%d", SERVER_BASE_PORT + j );
                        num_server_addresses++;
                    }
                }

                if ( num_server_addresses > 0 && netcode_generate_connect_token( num_server_addresses, server_address, CONNECT_TOKEN_EXPIRY, client_id, PROTOCOL_ID, 0, private_key, connect_token ) )
                {
                    netcode_client_connect( client[i], connect_token );
                }

                for ( j = 0; j < num_server_addresses; ++j )
                {
                    free( server_address[j] );
                }
            }
            
            if ( random_int( 0, 100 ) == 0 && netcode_client_state( client[i] ) == NETCODE_CLIENT_STATE_CONNECTED )
            {
                netcode_client_disconnect( client[i] );
            }

            if ( netcode_client_state( client[i] ) == NETCODE_CLIENT_STATE_CONNECTED ) 
            {
                netcode_client_send_packet( client[i], packet_data, random_int( 1, NETCODE_MAX_PACKET_SIZE ) );
            }

            netcode_client_update( client[i], time );
        }
    }
}

int main( int argc, char ** argv )
{
    int num_iterations = -1;

    if ( argc == 2 )
        num_iterations = atoi( argv[1] );

    printf( "[soak]\nnum_iterations = %d\n", num_iterations );

    initialize();

    printf( "starting\n" );

    signal( SIGINT, interrupt_handler );

    double time = 0.0;
    double delta_time = 0.1;

    if ( num_iterations > 0 )
    {
        int i;
        for ( i = 0; i < num_iterations; ++i )
        {
            if ( quit )
                break;

            run_iteration( time );

            time += delta_time;
        }
    }
    else
    {
        while ( !quit )
        {
            run_iteration( time );

            time += delta_time;
        }
    }

    shutdown();
	
    return 0;
}
