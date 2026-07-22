/*
    Drives a real netcode client through an invalid connect token scenario
    and prints every client state transition, for verify_state_machine.py.

    Output:  STATE <from> <to> <phase>
             RESULT <ok|fail> <note>
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "netcode.h"

static int last_state = -999;

static void note( struct netcode_client_t * client, const char * phase )
{
    int s = netcode_client_state( client );
    if ( s != last_state )
    {
        printf( "STATE %d %d %s\n", last_state == -999 ? 0 : last_state, s, phase );
        last_state = s;
    }
}

int main( void )
{
    setvbuf( stdout, NULL, _IONBF, 0 );

    if ( netcode_init() != NETCODE_OK ) { printf( "RESULT fail init\n" ); return 1; }
    netcode_log_level( NETCODE_LOG_LEVEL_NONE );

    double time = 100.0;
    const double dt = 0.1;
    uint8_t private_key[NETCODE_KEY_BYTES];
    memset( private_key, 0, sizeof( private_key ) );
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    memset( user_data, 0, sizeof( user_data ) );

    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:40502");
    NETCODE_CONST char * server_addresses[] = { addr };

    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    if ( netcode_generate_connect_token( 1, server_addresses, server_addresses, 30, 5,
                                         0x1234567890ABCDEFULL, 0x1122334455667788ULL,
                                         private_key, user_data, connect_token ) != NETCODE_OK )
    { printf( "RESULT fail token\n" ); return 1; }

    const int NUM_ADDR_OFFSET = 13 + 8 + 8 + 8 + 24 + 1024 + 4;
    uint32_t num_server_addresses = (connect_token[NUM_ADDR_OFFSET] |
                                    (connect_token[NUM_ADDR_OFFSET + 1] << 8) |
                                    (connect_token[NUM_ADDR_OFFSET + 2] << 16) |
                                    (connect_token[NUM_ADDR_OFFSET + 3] << 24));
    if (num_server_addresses != 1)
    {
        printf( "RESULT fail offset_wrong got=%u\n", num_server_addresses );
        return 1;
    }

    connect_token[NUM_ADDR_OFFSET] = 0;
    connect_token[NUM_ADDR_OFFSET + 1] = 0;
    connect_token[NUM_ADDR_OFFSET + 2] = 0;
    connect_token[NUM_ADDR_OFFSET + 3] = 0;

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );

    struct netcode_client_t * client = netcode_client_create( "0.0.0.0", &client_config, time );
    if ( !client ) { printf( "RESULT fail client_create\n" ); return 1; }

    note( client, "initial" );

    netcode_client_connect( client, connect_token );
    note( client, "after_connect_call" );

    int i;
    for ( i = 0; i < 200; i++ )
    {
        netcode_client_update( client, time );
        note( client, "validating" );
        if ( netcode_client_state( client ) < NETCODE_CLIENT_STATE_DISCONNECTED )
            break;
        time += dt;
    }

    int final_state = netcode_client_state( client );
    if ( final_state == NETCODE_CLIENT_STATE_INVALID_CONNECT_TOKEN )
        printf( "RESULT ok invalid_token\n" );
    else
        printf( "RESULT fail state=%d\n", final_state );

    netcode_client_destroy( client );
    netcode_term();
    return 0;
}
