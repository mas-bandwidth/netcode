#ifndef SPEEDNET_H
#define SPEEDNET_H

#include <stdint.h>

int speednet_init();

void speednet_term();

struct speednet_client_t * speednet_client_create();

void speednet_client_connect( struct speednet_client_t * client, const char * connect_token );

void speednet_client_update( struct speednet_client_t * client, double time );

int speednet_client_get_client_index( struct speednet_client_t * client );

int speednet_client_receive_packet_from_server( struct speednet_client_t * client, uint8_t * buffer, int buffer_length );

void speednet_client_send_packet_to_server( struct speednet_client_t * client, const uint8_t * packet_data, int packet_size );

void speednet_client_disconnect( struct speednet_client_t * client );

void speednet_client_destroy( struct speednet_client_t * client );

struct speednet_server_t * speednet_server_create( uint16_t port );

void speednet_server_start( struct speednet_server_t * server, int max_clients );

void speednet_server_update( struct speednet_server_t * server, double time );

int speednet_server_is_client_connected( struct speednet_server_t * server, int client_index );

int speednet_server_receive_packet_from_client( struct speednet_server_t * server, int client_index, uint8_t * buffer, int buffer_length );

void speednet_server_send_packet_to_client( struct speednet_server_t * server, int client_index, const uint8_t * packet_data, int packet_size );

void speednet_server_disconnect_client( struct speednet_server_t * server, int client_index );

void speednet_server_disconnect_all_clients( struct speednet_server_t * server );

void speednet_server_stop( struct speednet_server_t * server );

void speednet_server_destroy( struct speednet_server_t * server );

#endif // #ifndef SPEEDNET_H
