/*
    Drives a real netcode client through a connection-request timeout scenario
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

    struct netcode_client_config_t client_config;
    netcode_default_client_config( &client_config );

    struct netcode_client_t * client = netcode_client_create( "0.0.0.0", &client_config, time );
    if ( !client ) { printf( "RESULT fail client_create\n" ); return 1; }

    /* the initial state, before anything is asked of the client */
    note( client, "initial" );

    uint64_t client_id = 0x1234567890ABCDEFULL;
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    memset( user_data, 0, sizeof( user_data ) );
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];
    NETCODE_CONST char * server_addresses[] = { "127.0.0.1:40501" };

    if ( netcode_generate_connect_token( 1, server_addresses, server_addresses, 30, 5,
                                         client_id, 0x1122334455667788ULL,
                                         private_key, user_data, connect_token ) != NETCODE_OK )
    { printf( "RESULT fail token\n" ); return 1; }

    netcode_client_connect( client, connect_token );
    note( client, "after_connect_call" );

    int i;
    for ( i = 0; i < 2000; i++ )
    {
        netcode_client_update( client, time );
        note( client, "waiting" );
        if ( netcode_client_state( client ) < NETCODE_CLIENT_STATE_DISCONNECTED )
        { printf( "RESULT ok reached_error\n" ); return 0; }
        time += dt;
    }

    printf( "RESULT fail no_error_state\n" );

    netcode_client_destroy( client );
    netcode_term();
    return 1;
}
