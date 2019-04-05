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
#include <assert.h>
#include <string.h>
#include <signal.h>
#include <inttypes.h>

static volatile int quit = 0;

void interrupt_handler( int signal )
{
    (void) signal;
    quit = 1;
}

static uint8_t private_key[NETCODE_KEY_BYTES] = { 0x60, 0x6a, 0xbe, 0x6e, 0xc9, 0x19, 0x10, 0xea, 
                                                  0x9a, 0x65, 0x62, 0xf6, 0x6f, 0x2b, 0x30, 0xe4, 
                                                  0x43, 0x71, 0xd6, 0x2c, 0xd1, 0x99, 0x27, 0x26,
                                                  0x6b, 0x3c, 0x60, 0xf4, 0xb7, 0x15, 0xab, 0xa1 };

int main( int argc, char ** argv )
{
    (void) argc;
    (void) argv;

    if ( netcode_init() != NETCODE_OK )
    {
        printf( "error: failed to initialize netcode.io\n" );
        return 1;
    }

    netcode_log_level( NETCODE_LOG_LEVEL_INFO );

    double time = 0.0;
    double delta_time = 1.0 / 60.0;

    printf( "[server]\n" );

    #define TEST_PROTOCOL_ID 0x1122334455667788

    char * server_address = "127.0.0.1:40000";
    if ( argc == 2 )
        server_address = argv[1];

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = TEST_PROTOCOL_ID;
    memcpy( &server_config.private_key, private_key, NETCODE_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( server_address, &server_config, time );

    if ( !server )
    {
        printf( "error: failed to create server\n" );
        return 1;
    }

    netcode_server_start( server, NETCODE_MAX_CLIENTS );

    signal( SIGINT, interrupt_handler );

    uint8_t packet_data[NETCODE_MAX_PACKET_SIZE];
    int i;
    for ( i = 0; i < NETCODE_MAX_PACKET_SIZE; ++i )
        packet_data[i] = (uint8_t) i;

    while ( !quit )
    {
        netcode_server_update( server, time );

        if ( netcode_server_client_connected( server, 0 ) )
        {
            netcode_server_send_packet( server, 0, packet_data, NETCODE_MAX_PACKET_SIZE );
        }

        int client_index;
        for ( client_index = 0; client_index < NETCODE_MAX_CLIENTS; ++client_index )
        {
            while ( 1 )             
            {
                int packet_bytes;
                uint64_t packet_sequence;
                void * packet = netcode_server_receive_packet( server, client_index, &packet_bytes, &packet_sequence );
                if ( !packet )
                    break;
                (void) packet_sequence;
                assert( packet_bytes == NETCODE_MAX_PACKET_SIZE );
                assert( memcmp( packet, packet_data, NETCODE_MAX_PACKET_SIZE ) == 0 );            
                netcode_server_free_packet( server, packet );
            }
        }

        netcode_sleep( delta_time );

        time += delta_time;
    }

    if ( quit )
    {
        printf( "\nshutting down\n" );
    }

    netcode_server_destroy( server );

    netcode_term();
    
    return 0;
}
