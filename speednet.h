#ifndef SPEEDNET_H
#define SPEEDNET_H

#include <stdint.h>

int speednet_init();

void speednet_term();

struct speednet_client_t;

struct speednet_client_t * speednet_client_create();

void speednet_client_connect( struct speednet_client_t * client, const char * token );

void speednet_client_update( struct speednet_client_t * client, double time );

void speednet_client_send_packet_to_server( struct speednet_client_t * client, const uint8_t * packet_data, int packet_size );

int speednet_client_receive_packet_from_server( struct speednet_client_t * client, uint8_t * buffer, int buffer_length );

void speednet_client_disconnect( struct speednet_client_t * client );

void speednet_client_destroy( struct speednet_client_t * client );

#endif // #ifndef SPEEDNET_H
