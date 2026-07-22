/*
    Drives a real netcode client and server through a full connection lifecycle
    and prints every client state transition, for verify_state_machine.py.

    Output:  STATE <from> <to> <phase>
             RESULT <ok|fail> <note>
*/
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "netcode.h"

#define CONFORMANCE_PORT 41999

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
    const double dt = 0.05;
    uint8_t private_key[NETCODE_KEY_BYTES];
    memset( private_key, 0, sizeof( private_key ) );

    char addr[64];
    snprintf( addr, sizeof( addr ), "127.0.0.1:%d", CONFORMANCE_PORT );

    struct netcode_server_config_t server_config;
    netcode_default_server_config( &server_config );
    server_config.protocol_id = 0x1122334455667788ULL;
    memcpy( server_config.private_key, private_key, NETCODE_KEY_BYTES );

    struct netcode_server_t * server = netcode_server_create( addr, &server_config, time );
    if ( !server ) { printf( "RESULT fail server_create\n" ); return 1; }
    netcode_server_start( server, 4 );

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
    NETCODE_CONST char * server_addresses[] = { addr };

    if ( netcode_generate_connect_token( 1, server_addresses, server_addresses, 30, 5,
                                         client_id, server_config.protocol_id,
                                         private_key, user_data, connect_token ) != NETCODE_OK )
    { printf( "RESULT fail token\n" ); return 1; }

    netcode_client_connect( client, connect_token );
    note( client, "after_connect_call" );

    int i;
    for ( i = 0; i < 400; i++ )
    {
        netcode_client_update( client, time );
        netcode_server_update( server, time );
        note( client, "handshake" );
        if ( netcode_client_state( client ) == NETCODE_CLIENT_STATE_CONNECTED ) break;
        if ( netcode_client_state( client ) < NETCODE_CLIENT_STATE_DISCONNECTED )
        { printf( "RESULT fail handshake_error\n" ); return 1; }
        time += dt;
    }
    if ( netcode_client_state( client ) != NETCODE_CLIENT_STATE_CONNECTED )
    { printf( "RESULT fail never_connected\n" ); return 1; }

    /* hold the connection so a spurious transition would show up */
    for ( i = 0; i < 40; i++ )
    {
        netcode_client_update( client, time );
        netcode_server_update( server, time );
        note( client, "steady" );
        time += dt;
    }

    netcode_client_disconnect( client );
    note( client, "after_disconnect_call" );

    for ( i = 0; i < 20; i++ )
    {
        netcode_client_update( client, time );
        netcode_server_update( server, time );
        note( client, "post_disconnect" );
        time += dt;
    }

    printf( "RESULT ok complete\n" );

    netcode_client_destroy( client );
    netcode_server_destroy( server );
    netcode_term();
    return 0;
}
