#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "netcode.h"

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    if (netcode_init() != NETCODE_OK) {
        printf("RESULT fail init\n");
        return 1;
    }
    netcode_log_level(NETCODE_LOG_LEVEL_NONE);

    double time = 100.0;
    const double dt = 0.05;
    uint8_t private_key[NETCODE_KEY_BYTES];
    memset(private_key, 0, sizeof(private_key));

    char addr[64];
    snprintf(addr, sizeof(addr), "127.0.0.1:42000");

    struct netcode_server_config_t server_config;
    netcode_default_server_config(&server_config);
    server_config.protocol_id = 0x1122334455667788ULL;
    memcpy(server_config.private_key, private_key, NETCODE_KEY_BYTES);

    struct netcode_server_t *server = netcode_server_create(addr, &server_config, time);
    if (!server) {
        printf("RESULT fail server_create\n");
        return 1;
    }
    netcode_server_start(server, 4);

    int max_clients = netcode_server_max_clients(server);
    int num_connected = netcode_server_num_connected_clients(server);
    printf("SLOT baseline -1 %d max=%d\n", num_connected, max_clients);

    struct netcode_client_config_t client_config;
    netcode_default_client_config(&client_config);

    struct netcode_client_t *client = netcode_client_create("0.0.0.0", &client_config, time);
    if (!client) {
        printf("RESULT fail client_create\n");
        return 1;
    }

    uint64_t client_id = 0x1234567890ABCDEFULL;
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    memset(user_data, 0, sizeof(user_data));
    uint8_t connect_token[NETCODE_CONNECT_TOKEN_BYTES];

    NETCODE_CONST char * server_addresses[] = { addr };
    if (netcode_generate_connect_token(1, server_addresses, server_addresses, 30, 5,
                                         client_id, server_config.protocol_id,
                                         private_key, user_data, connect_token) != NETCODE_OK) {
        printf("RESULT fail token\n");
        return 1;
    }

    netcode_client_connect(client, connect_token);

    int connected_slots[max_clients];
    memset(connected_slots, 0, sizeof(connected_slots));

    for (int i = 0; i < 400; i++) {
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        num_connected = netcode_server_num_connected_clients(server);
        for (int j = 0; j < max_clients; j++) {
            if (netcode_server_client_connected(server, j)) {
                if (!connected_slots[j]) {
                    printf("SLOT connected %d %d id=%llu\n", j, num_connected, netcode_server_client_id(server, j));
                    connected_slots[j] = 1;
                }
            }
        }

        if (netcode_client_state(client) == NETCODE_CLIENT_STATE_CONNECTED) break;

        time += dt;
    }

    if (netcode_client_state(client) != NETCODE_CLIENT_STATE_CONNECTED) {
        printf("RESULT fail never_connected\n");
        netcode_client_destroy(client);
        netcode_server_destroy(server);
        netcode_term();
        return 1;
    }

    for (int i = 0; i < 20; i++) {
        int prev_num_connected = num_connected;
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        num_connected = netcode_server_num_connected_clients(server);
        if (num_connected != prev_num_connected) {
            printf("SLOT changed_while_idle -1 %d\n", num_connected);
        }

        time += dt;
    }

    netcode_client_disconnect(client);

    for (int i = 0; i < 100; i++) {
        netcode_client_update(client, time);
        netcode_server_update(server, time);

        num_connected = netcode_server_num_connected_clients(server);
        for (int j = 0; j < max_clients; j++) {
            if (!netcode_server_client_connected(server, j) && connected_slots[j]) {
                printf("SLOT freed %d %d\n", j, num_connected);
                connected_slots[j] = 0;
                break;
            }
        }

        time += dt;
    }

    printf("RESULT ok complete\n");

    netcode_client_destroy(client);
    netcode_server_destroy(server);
    netcode_term();
    return 0;
}
