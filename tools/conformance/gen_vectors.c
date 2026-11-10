#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "netcode.h"
struct keep_alive_t { uint8_t packet_type; int client_index; int max_clients; };
int netcode_write_packet( void*, uint8_t*, int, uint64_t, uint8_t*, uint64_t );
struct netcode_challenge_token_t;
void netcode_write_challenge_token( struct netcode_challenge_token_t *, uint8_t *, int );
int netcode_encrypt_challenge_token( uint8_t *, int, uint64_t, uint8_t * );
struct netcode_connect_token_private_t {
    uint64_t client_id;
    int timeout_seconds;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
};
void netcode_write_connect_token_private( struct netcode_connect_token_private_t *, uint8_t *, int );
int netcode_encrypt_connect_token_private( uint8_t *, int, uint8_t *, uint64_t, uint64_t, NETCODE_CONST uint8_t *, NETCODE_CONST uint8_t * );
static void fill_pattern( uint8_t * data, int bytes, uint8_t multiplier, uint8_t offset ){
    for(int i=0;i<bytes;i++) data[i]=(uint8_t)(i*multiplier+offset);
}
static void dump(const char*tag, uint8_t*b, int n){
    printf("%s %d ", tag, n);
    for(int i=0;i<n;i++) printf("%02x", b[i]);
    printf("\n");
}
int main(void){
    netcode_init();
    uint8_t key[32]; for(int i=0;i<32;i++) key[i]=(uint8_t)i;
    uint8_t user[256]; for(int i=0;i<256;i++) user[i]=(uint8_t)(255-i);
    uint8_t token[2048];
    const char *pub[2]={"127.0.0.1:40000","[::1]:40001"};
    const char *inn[2]={"127.0.0.1:40000","[::1]:40001"};
    if(netcode_generate_connect_token(2,(NETCODE_CONST char**)pub,(NETCODE_CONST char**)inn,
        45,17,0x1122334455667788ULL,0x1234567890ABCDEFULL,key,user,token)!=NETCODE_OK){
        fprintf(stderr,"token gen failed\n"); return 1; }
    dump("TOKEN", token, 2048);
    // packets: exercise the variable-length sequence encoding across byte boundaries
    uint64_t seqs[]={0,1,255,256,65535,65536,0xFFFFFF,0x1000000,0xFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
    for(unsigned s=0;s<sizeof(seqs)/sizeof(seqs[0]);s++){
        struct keep_alive_t ka={6+0,3,32}; ka.packet_type=4; /* keep alive */
        uint8_t buf[4096];
        int n=netcode_write_packet(&ka,buf,sizeof(buf),seqs[s],key,0x1234567890ABCDEFULL);
        if(n<=0){fprintf(stderr,"write_packet failed seq=%llu\n",(unsigned long long)seqs[s]);return 1;}
        printf("PKT %llu ", (unsigned long long)seqs[s]); dump("", buf, n);
    }

    /* challenge token, plaintext layout per STANDARD.md "Challenge Token" */
    {
        struct { uint64_t client_id; uint8_t user_data[256]; } ct;
        ct.client_id = 0x0102030405060708ULL;
        for ( int i = 0; i < 256; i++ ) ct.user_data[i] = (uint8_t)( i ^ 0x5A );
        uint8_t cbuf[300];
        netcode_write_challenge_token( (struct netcode_challenge_token_t*) &ct, cbuf, sizeof(cbuf) );
        dump( "CHALLENGE", cbuf, 300 );
    }

    /* known-answer encrypted wire vectors: packet, private connect token, challenge token */
    {
        uint64_t protocol_id = 0x1122334455667788ULL;
        uint64_t client_id = 0x0102030405060708ULL;
        uint64_t expire_timestamp = 0xAABBCCDD11223344ULL;
        uint64_t challenge_sequence = 0xFFEEDDCCBBAA9988ULL;
        uint8_t packet_key[32], private_key[32], challenge_key[32], c2s_key[32], s2c_key[32], nonce[24];
        fill_pattern( packet_key, 32, 7, 1 );
        fill_pattern( private_key, 32, 11, 3 );
        fill_pattern( challenge_key, 32, 13, 5 );
        fill_pattern( c2s_key, 32, 3, 1 );
        fill_pattern( s2c_key, 32, 5, 2 );
        fill_pattern( nonce, 24, 17, 9 );

        struct keep_alive_t ka = { 4, 10, 16 };
        uint8_t pbuf[4096];
        int pn = netcode_write_packet( &ka, pbuf, sizeof(pbuf), 0x44556677ULL, packet_key, protocol_id );
        if ( pn <= 0 ) { fprintf( stderr, "pkt_kat failed\n" ); return 1; }
        dump( "PKT_KAT", pbuf, pn );

        struct netcode_connect_token_private_t priv;
        memset( &priv, 0, sizeof(priv) );
        priv.client_id = client_id;
        priv.timeout_seconds = 15;
        priv.num_server_addresses = 3;
        netcode_parse_address( "127.0.0.1:40000", &priv.server_addresses[0] );
        netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:50000", &priv.server_addresses[1] );
        netcode_parse_address( "10.24.93.7:12345", &priv.server_addresses[2] );
        memcpy( priv.client_to_server_key, c2s_key, 32 );
        memcpy( priv.server_to_client_key, s2c_key, 32 );
        fill_pattern( priv.user_data, 256, 7, 13 );
        uint8_t priv_buf[1024];
        netcode_write_connect_token_private( &priv, priv_buf, sizeof(priv_buf) );
        if ( netcode_encrypt_connect_token_private( priv_buf, sizeof(priv_buf), (uint8_t*) "NETCODE 1.02",
            protocol_id, expire_timestamp, nonce, private_key ) != NETCODE_OK ) {
            fprintf( stderr, "privtoken_enc failed\n" ); return 1;
        }
        dump( "PRIVTOKEN_ENC", priv_buf, 1024 );

        struct { uint64_t client_id; uint8_t user_data[256]; } ct;
        ct.client_id = client_id;
        fill_pattern( ct.user_data, 256, 9, 17 );
        uint8_t cbuf[300];
        netcode_write_challenge_token( (struct netcode_challenge_token_t*) &ct, cbuf, sizeof(cbuf) );
        if ( netcode_encrypt_challenge_token( cbuf, sizeof(cbuf), challenge_sequence, challenge_key ) != NETCODE_OK ) {
            fprintf( stderr, "challenge_enc failed\n" ); return 1;
        }
        dump( "CHALLENGE_ENC", cbuf, 300 );
    }
    return 0;
}
