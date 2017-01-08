#ifndef NETCODE_H
#define NETCODE_H

#include <stdint.h>

int netcode_init();

void netcode_term();

struct netcode_client_t * netcode_client_create();

void netcode_client_connect( struct netcode_client_t * client, const char * connect_token );

void netcode_client_update( struct netcode_client_t * client, double time );

int netcode_client_get_client_index( struct netcode_client_t * client );

int netcode_client_receive_packet_from_server( struct netcode_client_t * client, uint8_t * buffer, int buffer_length );

void netcode_client_send_packet_to_server( struct netcode_client_t * client, const uint8_t * packet_data, int packet_size );

void netcode_client_disconnect( struct netcode_client_t * client );

void netcode_client_destroy( struct netcode_client_t * client );

struct netcode_server_t * netcode_server_create( uint16_t port );

void netcode_server_start( struct netcode_server_t * server, int max_clients );

void netcode_server_update( struct netcode_server_t * server, double time );

int netcode_server_is_client_connected( struct netcode_server_t * server, int client_index );

int netcode_server_receive_packet_from_client( struct netcode_server_t * server, int client_index, uint8_t * buffer, int buffer_length );

void netcode_server_send_packet_to_client( struct netcode_server_t * server, int client_index, const uint8_t * packet_data, int packet_size );

void netcode_server_disconnect_client( struct netcode_server_t * server, int client_index );

void netcode_server_disconnect_all_clients( struct netcode_server_t * server );

void netcode_server_stop( struct netcode_server_t * server );

void netcode_server_destroy( struct netcode_server_t * server );

#endif // #ifndef NETCODE_H
