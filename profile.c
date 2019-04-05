/*
    netcode.io reference implementation

    Copyright © 2017 - 2019, The Network Protocol Company, Inc.

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

#include "netcode.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <assert.h>
#include <signal.h>
#include <inttypes.h>

#define MAX_SERVERS NETCODE_MAX_SERVERS_PER_CONNECT
#define MAX_CLIENTS MAX_SERVERS * NETCODE_MAX_CLIENTS
#define SERVER_BASE_PORT 40000
#define CONNECT_TOKEN_EXPIRY 45
#define CONNECT_TOKEN_TIMEOUT 5
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

void profile_initialize()
{
    printf( "initializing\n" );

    netcode_init();

    memset( server, 0, sizeof( server ) );
    memset( client, 0, sizeof( client ) );

    netcode_random_bytes( private_key, NETCODE_KEY_BYTES );

    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; ++i )
    {
        packet_data[i] = (uint8_t) i;
    }

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, NETCODE_KEY_BYTES );

    for ( i = 0; i < MAX_SERVERS; ++i )
    {
        char server_address[256];
		#if _MSC_VER > 1600
        sprintf_s( server_address, 256, "127.0.0.1:%d", SERVER_BASE_PORT + i );
		#else
        sprintf( server_address, "127.0.0.1:%d", SERVER_BASE_PORT + i );
		#endif
        server[i] = netcode_server_create( server_address, &server_config, 0.0 );
    }

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );

    for ( i = 0; i < MAX_CLIENTS; ++i )
    {
        client[i] = netcode_client_create( "0.0.0.0", &client_config, 0.0 );
    }
}

void profile_shutdown()
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

void profile_iteration( double time )
{
    printf( "." );
    fflush( stdout );

    int i;

    for ( i = 0; i < MAX_SERVERS; ++i )
    {
        if ( server[i] != NULL )
        {
            if ( !netcode_server_running( server[i] ) )
            {
                netcode_server_start( server[i], random_int( 1, NETCODE_MAX_CLIENTS ) );
            }

            if ( netcode_server_running( server[i] ) )
            {
                int max_clients = netcode_server_max_clients( server[i] );
                int client_index;
                for ( client_index = 0; client_index < max_clients; ++client_index )
                {
                    if ( netcode_server_client_connected( server[i], client_index ) )
                    {
                        netcode_server_send_packet( server[i], 0, packet_data, NETCODE_MAX_PACKET_SIZE );
                    }
                }

                for ( client_index = 0; client_index < max_clients; ++client_index )
                {
                    if ( netcode_server_client_connected( server[i], client_index ) )
                    {
                        while ( 1 )             
                        {
                            int packet_bytes;
                            uint64_t packet_sequence;
                            void * packet = netcode_server_receive_packet( server[i], client_index, &packet_bytes, &packet_sequence );
                            if ( !packet )
                                break;
                            (void) packet_sequence;
                            assert( memcmp( packet, packet_data, packet_bytes ) == 0 );            
                            netcode_server_free_packet( server[i], packet );
                        }
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
            if ( netcode_client_state( client[i] ) <= NETCODE_CLIENT_STATE_DISCONNECTED )
            {
                uint64_t client_id = 0;
                netcode_random_bytes( (uint8_t*) &client_id, 8 );

                uint8_t user_data[NETCODE_USER_DATA_BYTES];
                netcode_random_bytes(user_data, NETCODE_USER_DATA_BYTES);

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
						#if _MSC_VER > 1600
                        sprintf_s( server_address[num_server_addresses], 256, "127.0.0.1:%d", SERVER_BASE_PORT + j );
						#else
                        sprintf( server_address[num_server_addresses], "127.0.0.1:%d", SERVER_BASE_PORT + j );
						#endif
                        num_server_addresses++;
                    }
                }

                if ( num_server_addresses > 0 && netcode_generate_connect_token( num_server_addresses, (NETCODE_CONST char**) server_address, (NETCODE_CONST char**) server_address, CONNECT_TOKEN_EXPIRY, CONNECT_TOKEN_TIMEOUT, client_id, PROTOCOL_ID, private_key, user_data, connect_token ) )
                {
                    netcode_client_connect( client[i], connect_token );
                }

                for ( j = 0; j < num_server_addresses; ++j )
                {
                    free( server_address[j] );
                }
            }
            
            if ( netcode_client_state( client[i] ) == NETCODE_CLIENT_STATE_CONNECTED ) 
            {
                netcode_client_send_packet( client[i], packet_data, NETCODE_MAX_PACKET_SIZE );

                while ( 1 )             
                {
                    int packet_bytes;
                    uint64_t packet_sequence;
                    void * packet = netcode_client_receive_packet( client[i], &packet_bytes, &packet_sequence );
                    if ( !packet )
                        break;
                    (void) packet_sequence;
                    assert( memcmp( packet, packet_data, packet_bytes ) == 0 );
                    netcode_client_free_packet( client[i], packet );
                }
            }

            netcode_client_update( client[i], time );
        }
    }
}

int main( int argc, char ** argv )
{
    int num_iterations = 100;

    if ( argc == 2 )
        num_iterations = atoi( argv[1] );

    profile_initialize();

    printf( "profiling" );

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

            profile_iteration( time );

            time += delta_time;
        }
    }
    else
    {
        while ( !quit )
        {
            profile_iteration( time );

            time += delta_time;
        }
    }

    profile_shutdown();
	
    return 0;
}
