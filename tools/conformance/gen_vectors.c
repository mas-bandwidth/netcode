#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "netcode.h"
struct keep_alive_t { uint8_t packet_type; int client_index; int max_clients; };
int netcode_write_packet( void*, uint8_t*, int, uint64_t, uint8_t*, uint64_t );
struct netcode_challenge_token_t;
void netcode_write_challenge_token( struct netcode_challenge_token_t *, uint8_t *, int );
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
    return 0;
}
