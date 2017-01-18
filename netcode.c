/*
    netcode.io reference implementation

    Copyright © 2016, The Network Protocol Company, Inc.

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

#include <netcode.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include <stdio.h>

#if    defined(__386__) || defined(i386)    || defined(__i386__)  \
    || defined(__X86)   || defined(_M_IX86)                       \
    || defined(_M_X64)  || defined(__x86_64__)                    \
    || defined(alpha)   || defined(__alpha) || defined(__alpha__) \
    || defined(_M_ALPHA)                                          \
    || defined(ARM)     || defined(_ARM)    || defined(__arm__)   \
    || defined(WIN32)   || defined(_WIN32)  || defined(__WIN32__) \
    || defined(_WIN32_WCE) || defined(__NT__)                     \
    || defined(__MIPSEL__)
  #define NETCODE_LITTLE_ENDIAN 1
#else
  #define NETCODE_BIG_ENDIAN 1
#endif

#define NETCODE_PLATFORM_WINDOWS    1
#define NETCODE_PLATFORM_MAC        2
#define NETCODE_PLATFORM_UNIX       3

#if defined(_WIN32)
#define NETCODE_PLATFORM NETCODE_PLATFORM_WINDOWS
#elif defined(__APPLE__)
#define NETCODE_PLATFORM NETCODE_PLATFORM_MAC
#else
#define NETCODE_PLATFORM NETCODE_PLATFORM_UNIX
#endif

#define NETCODE_CONNECT_TOKEN_BYTES 1024
#define NETCODE_CHALLENGE_TOKEN_BYTES 256
#define NETCODE_VERSION_INFO_BYTES 13
#define NETCODE_USER_DATA_BYTES 256
#define NETCODE_MAX_PACKET_BYTES 1220
#define NETCODE_MAX_PAYLOAD_BYTES 1200
#define NETCODE_MAX_ADDRESS_STRING_LENGTH 256

#define NETCODE_VERSION_INFO ( (uint8_t*) "NETCODE 1.00" )
#define NETCODE_PACKET_SEND_RATE 10.0
#define NETCODE_TIMEOUT_SECONDS 5.0

// ------------------------------------------------------------------

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    #define NOMINMAX
    #define _WINSOCK_DEPRECATED_NO_WARNINGS
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <ws2ipdef.h>
    #include <iphlpapi.h>
    #pragma comment( lib, "WS2_32.lib" )
    #pragma comment( lib, "IPHLPAPI.lib" )

    #ifdef SetPort
    #undef SetPort
    #endif // #ifdef SetPort

    #include <iphlpapi.h>
    #pragma comment( lib, "IPHLPAPI.lib" )
    
#elif NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

    #include <netdb.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <ifaddrs.h>
    #include <net/if.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>

#else

    #error netcode.io - unknown platform!

#endif

// ----------------------------------------------------------------

#define NETCODE_ADDRESS_NONE 0
#define NETCODE_ADDRESS_IPV4 1
#define NETCODE_ADDRESS_IPV6 2

struct netcode_address_t
{
    uint8_t type;
    union
    {
        uint8_t ipv4[4];
        uint16_t ipv6[8];
    } address;
    uint16_t port;
};

int netcode_parse_address( const char * address_string_in, struct netcode_address_t * address )
{
    assert( address_string_in );
    assert( address );

    memset( address, 0, sizeof( struct netcode_address_t ) );

    // first try to parse the string as an IPv6 address:
    // 1. if the first character is '[' then it's probably an ipv6 in form "[addr6]:portnum"
    // 2. otherwise try to parse as a raw IPv6 address using inet_pton

    #define NETCODE_ADDRESS_BUFFER_SAFETY 32

    char buffer[NETCODE_MAX_ADDRESS_STRING_LENGTH + NETCODE_ADDRESS_BUFFER_SAFETY*2];

    char * address_string = buffer + NETCODE_ADDRESS_BUFFER_SAFETY;
    strncpy( address_string, address_string_in, NETCODE_MAX_ADDRESS_STRING_LENGTH - 1 );
    address_string[NETCODE_MAX_ADDRESS_STRING_LENGTH-1] = '\0';

    int address_string_length = (int) strlen( address_string );

    if ( address_string[0] == '[' )
    {
        const int base_index = address_string_length - 1;
        
        for ( int i = 0; i < 6; ++i )         // note: no need to search past 6 characters as ":65535" is longest possible port value
        {
            const int index = base_index - i;
            if ( index < 3 )
                return 0;
            if ( address_string[index] == ':' )
            {
                address->port = (uint16_t) ( atoi( &address_string[index + 1] ) );
                address_string[index-1] = '\0';
            }
        }
        address_string += 1;
    }

    struct in6_addr sockaddr6;
    if ( inet_pton( AF_INET6, address_string, &sockaddr6 ) == 1 )
    {
        address->type = NETCODE_ADDRESS_IPV6;
        for ( int i = 0; i < 8; ++i )
        {
            address->address.ipv6[i] = ntohs( ( (uint16_t*) &sockaddr6 ) [i] );
        }
        return 1;
    }

    // otherwise it's probably an IPv4 address:
    // 1. look for ":portnum", if found save the portnum and strip it out
    // 2. parse remaining ipv4 address via inet_pton

    address_string_length = (int) strlen( address_string );
    const int base_index = address_string_length - 1;
    for ( int i = 0; i < 6; ++i )
    {
        const int index = base_index - i;
        if ( index < 0 )
            break;
        if ( address_string[index] == ':' )
        {
            address->port = (uint16_t) atoi( &address_string[index+1] );
            address_string[index] = '\0';
        }
    }

    struct sockaddr_in sockaddr4;
    if ( inet_pton( AF_INET, address_string, &sockaddr4.sin_addr ) == 1 )
    {
        address->type = NETCODE_ADDRESS_IPV4;
        address->address.ipv4[3] = ( sockaddr4.sin_addr.s_addr & 0xFF000000 ) >> 24;
        address->address.ipv4[2] = ( sockaddr4.sin_addr.s_addr & 0x00FF0000 ) >> 16;
        address->address.ipv4[1] = ( sockaddr4.sin_addr.s_addr & 0x0000FF00 ) >> 8;
        address->address.ipv4[0] = ( sockaddr4.sin_addr.s_addr & 0x000000FF ) >> 0;
        return 1;
    }

    return 0;
}

int netcode_address_equal( struct netcode_address_t * a, struct netcode_address_t * b )
{
    assert( a );
    assert( b );

    if ( a->type != b->type )
        return 0;

    if ( a->port != b->port )
        return 0;

    if ( a->type == NETCODE_ADDRESS_IPV4 )
    {
        int i;
        for ( i = 0; i < 4; ++i )
        {
            if ( a->address.ipv4[i] != b->address.ipv4[i] )
                return 0;
        }
    }
    else if ( a->type == NETCODE_ADDRESS_IPV6 )
    {
        int i;
        for ( i = 0; i < 8; ++i )
        {
            if ( a->address.ipv6[i] != b->address.ipv6[i] )
                return 0;
        }
    }
    else
    {
        return 0;
    }

    return 1;
}

// ----------------------------------------------------------------

struct netcode_t
{
    int initialized;
};

static struct netcode_t netcode;

int netcode_init()
{
    assert( !netcode.initialized );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    WSADATA WsaData;         
    int result = WSAStartup( MAKEWORD(2,2), &WsaData ) == NO_ERROR;
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    int result = 1;
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    if ( result )
        netcode.initialized = 1;

    return result;
}

void netcode_term()
{
    assert( netcode.initialized );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    WSACleanup();
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    netcode.initialized = 0;
}

// ----------------------------------------------------------------

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
typedef uint64_t netcode_socket_handle_t;
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
typedef int netcode_socket_handle_t;
#endif // #if NETCODE_PLATFORM == NETCODe_PLATFORM_WINDOWS

struct netcode_socket_t
{
    struct netcode_address_t address;
    netcode_socket_handle_t handle;
};

#define NETCODE_SOCKET_SNDBUF_SIZE     ( 1024 * 1024 )
#define NETCODE_SOCKET_RCVBUF_SIZE     ( 1024 * 1024 )

#define NETCODE_SOCKET_ERROR_NONE                               0
#define NETCODE_SOCKET_ERROR_CREATE_FAILED                      1
#define NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED            2
#define NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED           3
#define NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED              4
#define NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED              5
#define NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED                   6
#define NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED                   7
#define NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED           8
#define NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED           7

void netcode_socket_destroy( struct netcode_socket_t * socket )
{
    assert( socket );
    assert( netcode.initialized );

    if ( socket->handle != 0 )
    {
        #if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX
        close( socket->handle );
        #elif NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
        closesocket( socket->handle );
        #else
        #error unsupported platform
        #endif
        socket->handle = 0;
    }
}

int netcode_socket_create( struct netcode_socket_t * s, struct netcode_address_t * address, int send_buffer_size, int receive_buffer_size )
{
    assert( socket );
    assert( address );
    assert( netcode.initialized );

    assert( address->type != NETCODE_ADDRESS_NONE );

    s->address = *address;

    // create socket

    s->handle = socket( ( address->type == NETCODE_ADDRESS_IPV6 ) ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( s->handle == INVALID_SOCKET )
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( s->handle <= 0 )
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    {
        printf( "error: failed to create socket\n" );
        return NETCODE_SOCKET_ERROR_CREATE_FAILED;
    }

    // force IPv6 only if necessary

    if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        int yes = 1;
        if ( setsockopt( s->handle, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&yes, sizeof(yes) ) != 0 )
        {
            printf( "error: failed to set socket ipv6 only\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_SOCKOPT_IPV6_ONLY_FAILED;
        }
    }

    // increase socket send and receive buffer sizes

    if ( setsockopt( s->handle, SOL_SOCKET, SO_SNDBUF, (char*)&send_buffer_size, sizeof(int) ) != 0 )
    {
        printf( "error: failed to set socket send buffer size\n" );
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SOCKOPT_SNDBUF_FAILED;
    }

    if ( setsockopt( s->handle, SOL_SOCKET, SO_RCVBUF, (char*)&receive_buffer_size, sizeof(int) ) != 0 )
    {
        printf( "error: failed to set socket receive buffer size\n" );
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SOCKOPT_RCVBUF_FAILED;
    }

    // bind to port

    if ( address->type == NETCODE_ADDRESS_IPV6 )
    {
        struct sockaddr_in6 sock_address;
        memset( &sock_address, 0, sizeof( struct sockaddr_in6 ) );
        sock_address.sin6_family = AF_INET6;
        for ( int i = 0; i < 8; ++i )
        {
            ( (uint16_t*) &sock_address.sin6_addr ) [i] = htons( address->address.ipv6[i] );
        }
        sock_address.sin6_port = htons( address->port );

        if ( bind( s->handle, (struct sockaddr*) &sock_address, sizeof( sock_address ) ) < 0 )
        {
            printf( "error: failed to bind socket (ipv6)\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_BIND_IPV6_FAILED;
        }
    }
    else
    {
        struct sockaddr_in sock_address;
        sock_address.sin_family = AF_INET;
        sock_address.sin_addr.s_addr = ( ( (uint32_t) address->address.ipv4[0] ) << 24 ) | ( ( (uint32_t) address->address.ipv4[1] ) << 16 ) | ( ( (uint32_t) address->address.ipv4[2] ) << 8 ) | ( (uint32_t) address->address.ipv4[3] );
        sock_address.sin_port = htons( address->port );

        if ( bind( s->handle, (struct sockaddr*) &sock_address, sizeof( sock_address ) ) < 0 )
        {
            printf( "error: failed to bind socket (ipv4)\n" );
            netcode_socket_destroy( s );
            return NETCODE_SOCKET_ERROR_BIND_IPV4_FAILED;
        }
    }

    // if bound to port 0 find the actual port we got

    if ( address->port == 0 )
    {
        if ( address->type == NETCODE_ADDRESS_IPV6 )
        {
            struct sockaddr_in6 sin;
            socklen_t len = sizeof( sin );
            if ( getsockname( s->handle, (struct sockaddr*)&sin, &len ) == -1 )
            {
                printf( "error: failed to get socket port (ipv6)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV6_FAILED;
            }
            address->port = ntohs( sin.sin6_port );
        }
        else
        {
            struct sockaddr_in sin;
            socklen_t len = sizeof( sin );
            if ( getsockname( s->handle, (struct sockaddr*)&sin, &len ) == -1 )
            {
                printf( "error: failed to get socket port (ipv4)\n" );
                netcode_socket_destroy( s );
                return NETCODE_SOCKET_ERROR_GET_SOCKNAME_IPV4_FAILED;
            }
            address->port = ntohs( sin.sin_port );
        }
    }

    // set non-blocking io

#if NETCODE_PLATFORM == NETCODE_PLATFORM_MAC || NETCODE_PLATFORM == NETCODE_PLATFORM_UNIX

    int non_blocking = 1;
    if ( fcntl( s->handle, F_SETFL, O_NONBLOCK, non_blocking ) == -1 )
    {
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
    }

#elif YOJIMBO_PLATFORM == YOJIMBO_PLATFORM_WINDOWS

    DWORD nonBlocking = 1;
    if ( ioctlsocket( m_socket, FIONBIO, &nonBlocking ) != 0 )
    {
        netcode_socket_destroy( s );
        return NETCODE_SOCKET_ERROR_SET_NON_BLOCKING_FAILED;
    }

#else

    #error unsupported platform

#endif

    return NETCODE_SOCKET_ERROR_NONE;
}

void netcode_socket_send_packet( struct netcode_socket_t * socket, struct netcode_address_t * to, void * packet_data, int packet_bytes )
{
    assert( socket );
    assert( socket->handle != 0 );
    assert( to );
    assert( to->type == NETCODE_ADDRESS_IPV6 || to->type == NETCODE_ADDRESS_IPV4 );
    assert( packet_data );
    assert( packet_bytes > 0 );

    if ( to->type == NETCODE_ADDRESS_IPV6 )
    {
        struct sockaddr_in6 socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin6_family = AF_INET6;
        for ( int i = 0; i < 8; ++i )
        {
            ( (uint16_t*) &socket_address.sin6_addr ) [i] = htons( to->address.ipv6[i] );
        }
        socket_address.sin6_port = htons( to->port );
        sendto( socket->handle, (char*) packet_data, packet_bytes, 0, (struct sockaddr*) &socket_address, sizeof( struct sockaddr_in6 ) );
    }
    else if ( to->type == NETCODE_ADDRESS_IPV4 )
    {
        struct sockaddr_in socket_address;
        memset( &socket_address, 0, sizeof( socket_address ) );
        socket_address.sin_family = AF_INET;
        socket_address.sin_addr.s_addr = ( ( (uint32_t) to->address.ipv4[0] ) << 24 ) | ( ( (uint32_t) to->address.ipv4[1] ) << 16 ) | ( ( (uint32_t) to->address.ipv4[2] ) << 8 ) | ( (uint32_t) to->address.ipv4[3] );
        socket_address.sin_port = htons( to->port );
        sendto( socket->handle, (const char*) packet_data, packet_bytes, 0, (struct sockaddr*) &socket_address, sizeof( struct sockaddr_in ) );
    }
}

int netcode_socket_receive_packet( struct netcode_socket_t * socket, struct netcode_address_t * from, void * packet_data, int max_packet_size )
{
    assert( socket );
    assert( socket->handle != 0 );
    assert( from );
    assert( packet_data );
    assert( max_packet_size > 0 );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    typedef int socklen_t;
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    
    struct sockaddr_storage sockaddr_from;
    socklen_t from_length = sizeof( sockaddr_from );

    int result = recvfrom( socket->handle, (char*) packet_data, max_packet_size, 0, (struct sockaddr*) &sockaddr_from, &from_length );

#if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( result == SOCKET_ERROR )
    {
        int error = WSAGetLastError();

        if ( error == WSAEWOULDBLOCK )
            return 0;

        printf( "recvfrom failed with error %d\n", error );

        return 0;
    }
#else // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS
    if ( result <= 0 )
    {
        if ( errno == EAGAIN )
            return 0;

        printf( "recvfrom failed with error %d\n", errno );

        return 0;
    }
#endif // #if NETCODE_PLATFORM == NETCODE_PLATFORM_WINDOWS

    if ( sockaddr_from.ss_family == AF_INET6 )
    {
        struct sockaddr_in6 * addr_ipv6 = (struct sockaddr_in6*) &sockaddr_from;
        from->type = NETCODE_ADDRESS_IPV6;
        for ( int i = 0; i < 8; ++i )
        {
            from->address.ipv6[i] = ntohs( ( (uint16_t*) &addr_ipv6->sin6_addr ) [i] );
        }
        from->port = ntohs( addr_ipv6->sin6_port );
    }
    else if ( sockaddr_from.ss_family == AF_INET )
    {
        struct sockaddr_in * addr_ipv4 = (struct sockaddr_in*) &sockaddr_from;
        from->type = NETCODE_ADDRESS_IPV4;
        from->address.ipv4[0] = ( addr_ipv4->sin_addr.s_addr & 0xFF000000 ) >> 24;
        from->address.ipv4[1] = ( addr_ipv4->sin_addr.s_addr & 0x00FF0000 ) >> 16;
        from->address.ipv4[2] = ( addr_ipv4->sin_addr.s_addr & 0x0000FF00 ) >> 8;
        from->address.ipv4[3] = ( addr_ipv4->sin_addr.s_addr & 0x000000FF ) >> 0;
        from->port = ntohs( addr_ipv4->sin_port );
    }
    else
    {
        assert( 0 );
        return 0;
    }
  
    assert( result >= 0 );

    int bytes_read = result;

    return bytes_read;
}

// ----------------------------------------------------------------

void netcode_write_uint8( uint8_t ** p, uint8_t value )
{
    **p = value;
    ++(*p);
}

void netcode_write_uint16( uint8_t ** p, uint16_t value )
{
    (*p)[0] = value >> 8;
    (*p)[1] = value & 0xFF;
    *p += 2;
}

void netcode_write_uint32( uint8_t ** p, uint32_t value )
{
    (*p)[0] = value >> 24;
    (*p)[1] = ( value >> 16 ) & 0xFF;
    (*p)[2] = ( value >> 8  ) & 0xFF;
    (*p)[3] = value & 0xFF;
    *p += 4;
}

void netcode_write_uint64( uint8_t ** p, uint64_t value )
{
    (*p)[0] = value >> 56;
    (*p)[1] = ( value >> 48 ) & 0xFF;
    (*p)[2] = ( value >> 40 ) & 0xFF;
    (*p)[3] = ( value >> 32 ) & 0xFF;
    (*p)[4] = ( value >> 24 ) & 0xFF;
    (*p)[5] = ( value >> 16 ) & 0xFF;
    (*p)[6] = ( value >> 8  ) & 0xFF;
    (*p)[7] = value & 0xFF;
    *p += 8;
}

void netcode_write_bytes( uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; ++i )
    {
        netcode_write_uint8( p, byte_array[i] );
    }
}

uint8_t netcode_read_uint8( uint8_t ** p )
{
    uint8_t value = **p;
    ++(*p);
    return value;
}

uint16_t netcode_read_uint16( uint8_t ** p )
{
    uint16_t value;
    value  = ( ( (uint16_t)( (*p)[0] ) ) << 8 );
    value |= (*p)[1];
    *p += 2;
    return value;
}

uint32_t netcode_read_uint32( uint8_t ** p )
{
    uint32_t value;
    value  = ( ( (uint32_t)( (*p)[0] ) ) << 24 );
    value |= ( ( (uint32_t)( (*p)[1] ) ) << 16 );
    value |= ( ( (uint32_t)( (*p)[2] ) ) << 8 );
    value |= (*p)[3];
    *p += 4;
    return value;
}

uint64_t netcode_read_uint64( uint8_t ** p )
{
    uint64_t value;
    value  = ( ( (uint64_t)( (*p)[0] ) ) << 56 );
    value |= ( ( (uint64_t)( (*p)[1] ) ) << 48 );
    value |= ( ( (uint64_t)( (*p)[2] ) ) << 40 );
    value |= ( ( (uint64_t)( (*p)[3] ) ) << 32 );
    value |= ( ( (uint64_t)( (*p)[4] ) ) << 24 );
    value |= ( ( (uint64_t)( (*p)[5] ) ) << 16 );
    value |= ( ( (uint64_t)( (*p)[6] ) ) << 8  );
    value |= (*p)[7];
    *p += 8;
    return value;
}

void netcode_read_bytes( uint8_t ** p, uint8_t * byte_array, int num_bytes )
{
    int i;
    for ( i = 0; i < num_bytes; ++i )
    {
        byte_array[i] = netcode_read_uint8( p );
    }
}

// ----------------------------------------------------------------

#ifdef _MSC_VER
#define SODIUM_STATIC
#endif // #ifdef _MSC_VER

#include <sodium.h>

#if SODIUM_LIBRARY_VERSION_MAJOR > 7 || ( SODIUM_LIBRARY_VERSION_MAJOR && SODIUM_LIBRARY_VERSION_MINOR >= 3 )
#define SODIUM_SUPPORTS_OVERLAPPING_BUFFERS 1
#endif

void netcode_generate_key( uint8_t * key )
{
    assert( key );
    randombytes_buf( key, NETCODE_KEY_BYTES );
}

void netcode_random_bytes( uint8_t * data, int bytes )
{
    assert( data );
    assert( bytes > 0 );
    randombytes_buf( data, bytes );
}

int netcode_encrypt( uint8_t * message, int message_length, 
                     uint8_t * encrypted_message, int * encrypted_message_length, 
                     uint8_t * nonce, 
                     uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_secretbox_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_secretbox_MACBYTES );

    assert( message );
    assert( message_length > 0 );
    assert( encrypted_message );
    assert( encrypted_message_length );

    if ( crypto_secretbox_easy( encrypted_message, message, message_length, nonce, key ) != 0 )
        return 0;

    *encrypted_message_length = message_length + NETCODE_MAC_BYTES;

    return 1;
}

int netcode_decrypt( uint8_t * encrypted_message, int encrypted_message_length, 
                     uint8_t * decrypted_message, int * decrypted_message_length, 
                     uint8_t * nonce, 
                     uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_secretbox_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_secretbox_MACBYTES );

    if ( crypto_secretbox_open_easy( decrypted_message, encrypted_message, encrypted_message_length, nonce, key ) != 0 )
        return 0;

    *decrypted_message_length = encrypted_message_length - NETCODE_MAC_BYTES;

    return 1;
}

int netcode_encrypt_aead( uint8_t * message, uint64_t message_length, 
                          uint8_t * additional, uint64_t additional_length,
                          uint8_t * nonce,
                          uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_aead_chacha20poly1305_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_aead_chacha20poly1305_ABYTES );

    unsigned long long encrypted_length;

    #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

		int result = crypto_aead_chacha20poly1305_encrypt( message, &encrypted_length,
														   message, (unsigned long long) message_length,
														   additional, (unsigned long long) additional_length,
														   NULL, nonce, key );
	
		if ( result != 0 )
		    return 0;

	#else // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        uint8_t * temp = alloca( message_length + NETCODE_MAC_BYTES );

		int result = crypto_aead_chacha20poly1305_encrypt( temp, &encrypted_length,
														   message, (unsigned long long) message_length,
														   additional, (unsigned long long) additional_length,
														   NULL, nonce, key );
		
		if ( result != 0 )
		    return 0;
	
        memcpy( message, temp, message_length + NETCODE_MAC_BYTES );

	#endif // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

    assert( encrypted_length == message_length + NETCODE_MAC_BYTES );

    return 1;
}

int netcode_decrypt_aead( uint8_t * message, uint64_t message_length, 
                          uint8_t * additional, uint64_t additional_length,
                          uint8_t * nonce,
                          uint8_t * key )
{
    assert( NETCODE_KEY_BYTES == crypto_aead_chacha20poly1305_KEYBYTES );
    assert( NETCODE_MAC_BYTES == crypto_aead_chacha20poly1305_ABYTES );

    unsigned long long decrypted_length;

    #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

		int result = crypto_aead_chacha20poly1305_decrypt( message, &decrypted_length,
														   NULL,
														   message, (unsigned long long) message_length,
														   additional, (unsigned long long) additional_length,
														   nonce, key );

		if ( result != 0 )
			return 0;

	#else // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

        uint8_t * temp = alloca( message_length );

		int result = crypto_aead_chacha20poly1305_decrypt( temp, &decrypted_length,
														   NULL,
														   message, (unsigned long long) message_length,
														   additional, (unsigned long long) additional_length,
														   nonce, key );
		
		if ( result != 0 )
		    return 0;
	
        memcpy( message, temp, decrypted_length );

	#endif // #if SODIUM_SUPPORTS_OVERLAPPING_BUFFERS

    assert( decrypted_length == message_length - NETCODE_MAC_BYTES );

    return 1;
}

// ----------------------------------------------------------------

struct netcode_connect_token_t
{
    uint64_t client_id;
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
    uint8_t user_data[NETCODE_USER_DATA_BYTES];
};

void netcode_generate_connect_token( struct netcode_connect_token_t * connect_token, uint64_t client_id, int num_server_addresses, struct netcode_address_t * server_addresses, uint8_t * user_data )
{
    assert( connect_token );
    assert( num_server_addresses > 0 );
    assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    assert( server_addresses );
    assert( user_data );

    connect_token->client_id = client_id;
    
    connect_token->num_server_addresses = num_server_addresses;
    
    int i;
    for ( i = 0; i < num_server_addresses; ++i )
    {
        memcpy( &connect_token->server_addresses[i], &server_addresses[i], sizeof( struct netcode_address_t ) );
    }

    netcode_generate_key( connect_token->client_to_server_key );
    netcode_generate_key( connect_token->server_to_client_key );

    memcpy( connect_token->user_data, user_data, NETCODE_USER_DATA_BYTES );
}

void netcode_write_connect_token( struct netcode_connect_token_t * connect_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

	assert( connect_token );
    assert( connect_token->num_server_addresses > 0 );
    assert( connect_token->num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
	assert( buffer );
    assert( buffer_length >= NETCODE_CONNECT_TOKEN_BYTES );

    memset( buffer, 0, NETCODE_CONNECT_TOKEN_BYTES );

    uint8_t * start = buffer;

    netcode_write_uint64( &buffer, connect_token->client_id );

    netcode_write_uint32( &buffer, connect_token->num_server_addresses );

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV4 );
            for ( j = 0; j < 4; ++j )
            {
                netcode_write_uint8( &buffer, connect_token->server_addresses[i].address.ipv4[j] );
            }
            netcode_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV6 );
            for ( j = 0; j < 8; ++j )
            {
                netcode_write_uint16( &buffer, connect_token->server_addresses[i].address.ipv6[j] );
            }
            netcode_write_uint16( &buffer, connect_token->server_addresses[i].port );
        }
        else
        {
            assert( 0 );
        }
    }

    netcode_write_bytes( &buffer, connect_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, connect_token->server_to_client_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, connect_token->user_data, NETCODE_USER_DATA_BYTES );

    assert( buffer - start <= NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

int netcode_encrypt_connect_token( uint8_t * buffer, int buffer_length, uint8_t * version_info, uint64_t protocol_id, uint64_t expire_timestamp, uint64_t sequence, uint8_t * key )
{
    assert( buffer );
    assert( buffer_length == NETCODE_CONNECT_TOKEN_BYTES );
    assert( key );

    uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
		netcode_write_bytes( &p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &p, protocol_id );
        netcode_write_uint64( &p, expire_timestamp );
    }

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

    if ( !netcode_encrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES, additional_data, sizeof( additional_data ), nonce, key ) )
        return 0;

    return 1;
}

int netcode_decrypt_connect_token( uint8_t * buffer, int buffer_length, uint8_t * version_info, uint64_t protocol_id, uint64_t expire_timestamp, uint64_t sequence, uint8_t * key )
{
	assert( buffer );
    assert( buffer_length == NETCODE_CONNECT_TOKEN_BYTES );
	assert( key );

    uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+8];
    {
        uint8_t * p = additional_data;
		netcode_write_bytes( &p, version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &p, protocol_id );
        netcode_write_uint64( &p, expire_timestamp );
    }

    uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

    if ( !netcode_decrypt_aead( buffer, NETCODE_CONNECT_TOKEN_BYTES, additional_data, sizeof( additional_data ), nonce, key ) )
        return 0;

	memset( buffer + NETCODE_CONNECT_TOKEN_BYTES - NETCODE_MAC_BYTES, 0, NETCODE_MAC_BYTES );

	return 1;
}

int netcode_read_connect_token( uint8_t * buffer, int buffer_length, struct netcode_connect_token_t * connect_token )
{
    assert( buffer );
    assert( connect_token );

    if ( buffer_length < NETCODE_CONNECT_TOKEN_BYTES )
        return 0;
    
    connect_token->client_id = netcode_read_uint64( &buffer );

    connect_token->num_server_addresses = netcode_read_uint32( &buffer );

    if ( connect_token->num_server_addresses <= 0 )
        return 0;

    if ( connect_token->num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
        return 0;

    int i,j;

    for ( i = 0; i < connect_token->num_server_addresses; ++i )
    {
        connect_token->server_addresses[i].type = netcode_read_uint8( &buffer );

        if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            for ( j = 0; j < 4; ++j )
            {
                connect_token->server_addresses[i].address.ipv4[j] = netcode_read_uint8( &buffer );
            }
            connect_token->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else if ( connect_token->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            for ( j = 0; j < 8; ++j )
            {
                connect_token->server_addresses[i].address.ipv6[j] = netcode_read_uint16( &buffer );
            }
            connect_token->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else
        {
            return 0;
        }
    }

    netcode_read_bytes( &buffer, connect_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, connect_token->server_to_client_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, connect_token->user_data, NETCODE_USER_DATA_BYTES );

    return 1;
}

// -----------------------------------------------

struct netcode_challenge_token_t
{
    uint64_t client_id;
    uint8_t connect_token_mac[NETCODE_MAC_BYTES];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
};

void netcode_write_challenge_token( struct netcode_challenge_token_t * challenge_token, uint8_t * buffer, int buffer_length )
{
    (void) buffer_length;

    assert( challenge_token );
    assert( buffer );
    assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );

    memset( buffer, 0, NETCODE_CHALLENGE_TOKEN_BYTES );

    uint8_t * start = buffer;

    netcode_write_uint64( &buffer, challenge_token->client_id );

    netcode_write_bytes( &buffer, challenge_token->connect_token_mac, NETCODE_MAC_BYTES );

    netcode_write_bytes( &buffer, challenge_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, challenge_token->server_to_client_key, NETCODE_KEY_BYTES );

    assert( buffer - start <= NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );
}

int netcode_encrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key )
{
	assert( buffer );
	assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
	assert( key );

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

	int encrypted_bytes = 0;

	if ( !netcode_encrypt( buffer, NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, buffer, &encrypted_bytes, nonce, key ) )
		return 0;

	assert( encrypted_bytes == NETCODE_CHALLENGE_TOKEN_BYTES );

	return 1;
}

int netcode_decrypt_challenge_token( uint8_t * buffer, int buffer_length, uint64_t sequence, uint8_t * key )
{
	assert( buffer );
	assert( buffer_length >= NETCODE_CHALLENGE_TOKEN_BYTES );
	assert( key );

	uint8_t nonce[8];
    {
        uint8_t * p = nonce;
        netcode_write_uint64( &p, sequence );
    }

	int decrypted_bytes = 0;

	if ( !netcode_decrypt( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, buffer, &decrypted_bytes, nonce, key ) )
		return 0;

	assert( decrypted_bytes == NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES );

	memset( buffer + NETCODE_CHALLENGE_TOKEN_BYTES - NETCODE_MAC_BYTES, 0, NETCODE_MAC_BYTES );

	return 1;
}

int netcode_read_challenge_token( uint8_t * buffer, int buffer_length, struct netcode_challenge_token_t * challenge_token )
{
    assert( buffer );
    assert( challenge_token );

    if ( buffer_length < NETCODE_CHALLENGE_TOKEN_BYTES )
        return 0;

    uint8_t * start = buffer;
    
    challenge_token->client_id = netcode_read_uint64( &buffer );

    netcode_read_bytes( &buffer, challenge_token->connect_token_mac, NETCODE_MAC_BYTES );

	netcode_read_bytes( &buffer, challenge_token->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, challenge_token->server_to_client_key, NETCODE_KEY_BYTES );

	assert( buffer - start == 8 + NETCODE_MAC_BYTES + NETCODE_KEY_BYTES + NETCODE_KEY_BYTES );

    return 1;
}

// ----------------------------------------------------------------

#define NETCODE_CONNECTION_REQUEST_PACKET           0
#define NETCODE_CONNECTION_DENIED_PACKET            1
#define NETCODE_CONNECTION_CHALLENGE_PACKET         2
#define NETCODE_CONNECTION_RESPONSE_PACKET          3
#define NETCODE_CONNECTION_CONFIRM_PACKET           4
#define NETCODE_CONNECTION_KEEP_ALIVE_PACKET        5
#define NETCODE_CONNECTION_PAYLOAD_PACKET           6
#define NETCODE_CONNECTION_DISCONNECT_PACKET        7
#define NETCODE_CONNECTION_NUM_PACKETS              8

struct netcode_connection_request_packet_t
{
    uint8_t packet_type;
    uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
    uint64_t protocol_id;
    uint64_t connect_token_expire_timestamp;
    uint64_t connect_token_sequence;
    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];
};

#define NETCODE_CONNECTION_REQUEST_DENIED_REASON_SERVER_IS_FULL 0

struct netcode_connection_denied_packet_t
{
    uint8_t packet_type;
    uint32_t reason;
};

struct netcode_connection_challenge_packet_t
{
    uint8_t packet_type;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
};

struct netcode_connection_response_packet_t
{
    uint8_t packet_type;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
};

struct netcode_connection_confirm_packet_t
{
    uint8_t packet_type;
    uint32_t client_index;
};

struct netcode_connection_keep_alive_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_payload_packet_t
{
    uint8_t packet_type;
    uint32_t payload_bytes;
    uint8_t payload_data[1];
    // ...
};

struct netcode_connection_disconnect_packet_t
{
    uint8_t packet_type;
};

struct netcode_connection_payload_packet_t * netcode_create_payload_packet( int payload_bytes )
{
    assert( payload_bytes >= 0 );
    assert( payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

    struct netcode_connection_payload_packet_t * packet = (struct netcode_connection_payload_packet_t*) malloc( sizeof( struct netcode_connection_payload_packet_t ) + payload_bytes );

    if ( !packet )
        return NULL;
    
    packet->packet_type = NETCODE_CONNECTION_PAYLOAD_PACKET;
    packet->payload_bytes = payload_bytes;

    return packet;
}

struct netcode_packet_context_t
{
    uint64_t protocol_id;
    uint64_t current_timestamp;
	uint8_t connect_token_key[NETCODE_KEY_BYTES];
	uint8_t write_packet_key[NETCODE_KEY_BYTES];
	uint8_t read_packet_key[NETCODE_KEY_BYTES];
};

int netcode_sequence_number_bytes_required( uint64_t sequence )
{
    int i;
    uint64_t mask = 0xFF00000000000000UL;
    for ( i = 0; i < 7; ++i )
    {
        if ( sequence & mask )
            break;
        mask >>= 8;
    }
    return 8 - i;
}

int netcode_write_packet( void * packet, uint8_t * buffer, int buffer_length, uint64_t sequence, struct netcode_packet_context_t * context )
{
    (void) context;

    uint8_t packet_type = ((uint8_t*)packet)[0];

    if ( packet_type == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        assert( buffer_length >= 1 + 13 + 8 + 8 + 8 + NETCODE_CONNECT_TOKEN_BYTES );

        struct netcode_connection_request_packet_t * p = (struct netcode_connection_request_packet_t*) packet;

        uint8_t * start = buffer;

        netcode_write_uint8( &buffer, NETCODE_CONNECTION_REQUEST_PACKET );
		netcode_write_bytes( &buffer, p->version_info, NETCODE_VERSION_INFO_BYTES );
        netcode_write_uint64( &buffer, p->protocol_id );
        netcode_write_uint64( &buffer, p->connect_token_expire_timestamp );
        netcode_write_uint64( &buffer, p->connect_token_sequence );
        netcode_write_bytes( &buffer, p->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 1 + 13 + 8 + 8 + 8 + NETCODE_CONNECT_TOKEN_BYTES );

        return (int) ( buffer - start );
    }
    else
    {
        // *** encrypted packets ***

        // write the prefix byte (this is a combination of the packet type and number of sequence bytes)

        uint8_t * start = buffer;

		uint8_t sequence_bytes = (uint8_t) netcode_sequence_number_bytes_required( sequence );

		assert( sequence_bytes >= 1 );
		assert( sequence_bytes <= 7 );

        assert( packet_type <= 0xF );

        uint8_t prefix_byte = packet_type | ( sequence_bytes << 4 );

        netcode_write_uint8( &buffer, prefix_byte );

		// write the variable length sequence number [1,7] bytes.

		uint64_t sequence_temp = sequence;

		int i;
		for ( i = 0; i < sequence_bytes; ++i )
		{
			netcode_write_uint8( &buffer, (uint8_t) ( sequence_temp & 0xFF ) );
			sequence_temp >>= 8;
		}

        // write packet data according to type. this data will be encrypted.

        uint8_t * encrypted_start = buffer;

		switch ( packet_type )
		{
			case NETCODE_CONNECTION_DENIED_PACKET:
			{
                struct netcode_connection_denied_packet_t * p = (struct netcode_connection_denied_packet_t*) packet;
                netcode_write_uint32( &buffer, p->reason );
			}
			break;

			case NETCODE_CONNECTION_CHALLENGE_PACKET:
			{
				struct netcode_connection_challenge_packet_t * p = (struct netcode_connection_challenge_packet_t*) packet;
				netcode_write_uint64( &buffer, p->challenge_token_sequence );
				netcode_write_bytes( &buffer, p->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
			}
			break;

			case NETCODE_CONNECTION_RESPONSE_PACKET:
			{
                struct netcode_connection_response_packet_t * p = (struct netcode_connection_response_packet_t*) packet;
                netcode_write_uint64( &buffer, p->challenge_token_sequence );
                netcode_write_bytes( &buffer, p->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
			}
			break;

			case NETCODE_CONNECTION_CONFIRM_PACKET:
			{
                struct netcode_connection_confirm_packet_t * p = (struct netcode_connection_confirm_packet_t*) packet;
                netcode_write_uint32( &buffer, p->client_index );
			}
			break;
			
			case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
			{
                // ...
			}
			break;

			case NETCODE_CONNECTION_PAYLOAD_PACKET:
			{
				struct netcode_connection_payload_packet_t * p = (struct netcode_connection_payload_packet_t*) packet;

                assert( p->payload_bytes <= NETCODE_MAX_PAYLOAD_BYTES );

				netcode_write_bytes( &buffer, p->payload_data, p->payload_bytes );
			}
			break;

			case NETCODE_CONNECTION_DISCONNECT_PACKET:
			{
				// ...
			}
			break;

			default:
				assert( 0 );
		}

        assert( buffer - start <= buffer_length - NETCODE_MAC_BYTES );

        uint8_t * encrypted_finish = buffer;

        // encrypt the per-packet packet written with the prefix byte, protocol id and version as the associated data. this must match to decrypt.

		uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+1];
		{
			uint8_t * p = additional_data;
			netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
			netcode_write_uint64( &p, context->protocol_id );
			netcode_write_uint8( &p, prefix_byte );
		}

        uint8_t nonce[NETCODE_NONCE_BYTES];
        {
            uint8_t * p = nonce;
            netcode_write_uint64( &p, sequence );
        }

        if ( !netcode_encrypt_aead( encrypted_start, encrypted_finish - encrypted_start, additional_data, sizeof( additional_data ), nonce, context->write_packet_key ) )
            return 0;

        buffer += NETCODE_MAC_BYTES;

		assert( buffer - start <= buffer_length );

        return (int) ( buffer - start );
    }
}

void * netcode_read_packet( uint8_t * buffer, int buffer_length, uint64_t * sequence, struct netcode_packet_context_t * context, uint8_t * allowed_packet_types )
{
    assert( context );
	assert( sequence );
    assert( allowed_packet_types );

	*sequence = 0;

	if ( buffer_length < 1 )
		return NULL;

    uint8_t * start = buffer;

    uint8_t prefix_byte = netcode_read_uint8( &buffer );

    if ( prefix_byte == NETCODE_CONNECTION_REQUEST_PACKET )
    {
        // connection request packet: first byte is zero

        if ( !allowed_packet_types[0] )
            return NULL;

        if ( buffer_length != 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + 8 + NETCODE_CONNECT_TOKEN_BYTES )
            return NULL;

		uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
		netcode_read_bytes( &buffer, version_info, NETCODE_VERSION_INFO_BYTES );
		if ( version_info[0]  != 'N' || 
			 version_info[1]  != 'E' || 
			 version_info[2]  != 'T' || 
			 version_info[3]  != 'C' || 
			 version_info[4]  != 'O' ||
			 version_info[5]  != 'D' ||
			 version_info[6]  != 'E' ||
			 version_info[7]  != ' ' || 
			 version_info[8]  != '1' ||
			 version_info[9]  != '.' ||
			 version_info[10] != '0' ||
			 version_info[11] != '0' ||
			 version_info[12] != '\0' )
		{
			return NULL;
		}

        uint64_t packet_protocol_id = netcode_read_uint64( &buffer );
        if ( packet_protocol_id != context->protocol_id )
            return NULL;

        uint64_t packet_connect_token_expire_timestamp = netcode_read_uint64( &buffer );
        if ( packet_connect_token_expire_timestamp <= context->current_timestamp )
            return NULL;

		uint64_t packet_connect_token_sequence = netcode_read_uint64( &buffer );

		assert( buffer - start == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + 8 );

		if ( !netcode_decrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, version_info, context->protocol_id, packet_connect_token_expire_timestamp, packet_connect_token_sequence, context->connect_token_key ) )
			return NULL;

        struct netcode_connection_request_packet_t * packet = (struct netcode_connection_request_packet_t*) malloc( sizeof( struct netcode_connection_request_packet_t ) );

        if ( !packet )
            return NULL;

        packet->packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
		memcpy( packet->version_info, version_info, NETCODE_VERSION_INFO_BYTES );
        packet->protocol_id = packet_protocol_id;
        packet->connect_token_expire_timestamp = packet_connect_token_expire_timestamp;
		packet->connect_token_sequence = packet_connect_token_sequence;
        netcode_read_bytes( &buffer, packet->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

        assert( buffer - start == 1 + NETCODE_VERSION_INFO_BYTES + 8 + 8 + 8 + NETCODE_CONNECT_TOKEN_BYTES );

        return packet;
    }
    else
    {
        // *** encrypted packets ***

        // extract the packet type and number of sequence bytes from the prefix byte

        if ( buffer_length < 1 + 1 + NETCODE_MAC_BYTES )
            return NULL;

        int packet_type = prefix_byte & 0xF;

        if ( packet_type >= NETCODE_CONNECTION_NUM_PACKETS )
            return NULL;

        if ( !allowed_packet_types[packet_type] )
            return NULL;

        int sequence_bytes = prefix_byte >> 4;

        if ( sequence_bytes < 1 || sequence_bytes > 7 )
            return NULL;

        if ( buffer_length < 1 + sequence_bytes + NETCODE_MAC_BYTES )
            return NULL;

        // read variable length sequence number [1,7]

        int i;
        for ( i = 0; i < sequence_bytes; ++i )
        {
			uint8_t value = netcode_read_uint8( &buffer );
            (*sequence) |= ( value << ( 8 * i ) );
        }

        // decrypt the per-packet type data

		uint8_t additional_data[NETCODE_VERSION_INFO_BYTES+8+1];
		{
			uint8_t * p = additional_data;
			netcode_write_bytes( &p, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
			netcode_write_uint64( &p, context->protocol_id );
			netcode_write_uint8( &p, prefix_byte );
		}

        uint8_t nonce[NETCODE_NONCE_BYTES];
        {
            uint8_t * p = nonce;
            netcode_write_uint64( &p, *sequence );
        }

		int encrypted_bytes = (int) ( buffer_length - ( buffer - start ) );

        if ( encrypted_bytes < NETCODE_MAC_BYTES )
            return NULL;

        if ( !netcode_decrypt_aead( buffer, encrypted_bytes, additional_data, sizeof( additional_data ), nonce, context->read_packet_key ) )
            return NULL;

		int decrypted_bytes = encrypted_bytes - NETCODE_MAC_BYTES;

        // process the per-packet type data that was just decrypted
        
        switch ( packet_type )
        {
            case NETCODE_CONNECTION_DENIED_PACKET:
            {
				if ( decrypted_bytes != 4 )
					return NULL;

                struct netcode_connection_denied_packet_t * packet = (struct netcode_connection_denied_packet_t*) malloc( sizeof( struct netcode_connection_denied_packet_t ) );

				if ( !packet )
					return NULL;
				
				packet->packet_type = NETCODE_CONNECTION_DENIED_PACKET;
                packet->reason = netcode_read_uint32( &buffer );
				
				return packet;
            }
            break;

            case NETCODE_CONNECTION_CHALLENGE_PACKET:
            {
				if ( decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES )
					return NULL;

                struct netcode_connection_challenge_packet_t * packet = (struct netcode_connection_challenge_packet_t*) malloc( sizeof( struct netcode_connection_challenge_packet_t ) );

				if ( !packet )
					return NULL;
				
				packet->packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
				packet->challenge_token_sequence = netcode_read_uint64( &buffer );
				netcode_read_bytes( &buffer, packet->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
				
				return packet;
			}
            break;

            case NETCODE_CONNECTION_RESPONSE_PACKET:
            {
                if ( decrypted_bytes != 8 + NETCODE_CHALLENGE_TOKEN_BYTES )
                    return NULL;

                struct netcode_connection_response_packet_t * packet = (struct netcode_connection_response_packet_t*) malloc( sizeof( struct netcode_connection_response_packet_t ) );

                if ( !packet )
                    return NULL;
                
                packet->packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
                packet->challenge_token_sequence = netcode_read_uint64( &buffer );
                netcode_read_bytes( &buffer, packet->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );
                
                return packet;
            }
            break;

            case NETCODE_CONNECTION_CONFIRM_PACKET:
            {
                if ( decrypted_bytes != 4 )
                    return NULL;

                struct netcode_connection_confirm_packet_t * packet = (struct netcode_connection_confirm_packet_t*) malloc( sizeof( struct netcode_connection_confirm_packet_t ) );

                if ( !packet )
                    return NULL;
                
                packet->packet_type = NETCODE_CONNECTION_CONFIRM_PACKET;
                packet->client_index = netcode_read_uint32( &buffer );
                
                return packet;
            }
            break;
            
            case NETCODE_CONNECTION_KEEP_ALIVE_PACKET:
            {
				if ( decrypted_bytes != 0 )
					return NULL;

                struct netcode_connection_keep_alive_packet_t * packet = (struct netcode_connection_keep_alive_packet_t*) malloc( sizeof( struct netcode_connection_keep_alive_packet_t ) );

				if ( !packet )
					return NULL;
				
				packet->packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;
				
				return packet;
            }
            break;

            case NETCODE_CONNECTION_PAYLOAD_PACKET:
            {
                if ( decrypted_bytes > NETCODE_MAX_PAYLOAD_BYTES )
                    return NULL;

                struct netcode_connection_payload_packet_t * packet = netcode_create_payload_packet( decrypted_bytes );

                if ( !packet )
                    return NULL;
                
                memcpy( packet->payload_data, buffer, decrypted_bytes );
                
                return packet;
            }
            break;

            case NETCODE_CONNECTION_DISCONNECT_PACKET:
            {
				if ( decrypted_bytes != 0 )
					return NULL;

                struct netcode_connection_disconnect_packet_t * packet = (struct netcode_connection_disconnect_packet_t*) malloc( sizeof( struct netcode_connection_disconnect_packet_t ) );

				if ( !packet )
					return NULL;
				
				packet->packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;
				
				return packet;
            }
            break;

            default:
                return NULL;
        }
    }
}

// ----------------------------------------------------------------

struct netcode_server_info_t
{
    uint8_t version_info[NETCODE_VERSION_INFO_BYTES];
    uint64_t protocol_id;
    uint64_t connect_token_create_timestamp;
    uint64_t connect_token_expire_timestamp;
    uint64_t connect_token_sequence;
    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];
    int num_server_addresses;
    struct netcode_address_t server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];
    uint8_t client_to_server_key[NETCODE_KEY_BYTES];
    uint8_t server_to_client_key[NETCODE_KEY_BYTES];
    int timeout_seconds;
};

void netcode_write_server_info( struct netcode_server_info_t * server_info, uint8_t * buffer, int buffer_length )
{
    assert( server_info );
    assert( buffer );
    assert( buffer_length >= NETCODE_SERVER_INFO_BYTES );

    uint8_t * start = buffer;

    netcode_write_bytes( &buffer, server_info->version_info, NETCODE_VERSION_INFO_BYTES );

    netcode_write_uint64( &buffer, server_info->protocol_id );

    netcode_write_uint64( &buffer, server_info->connect_token_create_timestamp );

    netcode_write_uint64( &buffer, server_info->connect_token_expire_timestamp );

    netcode_write_uint64( &buffer, server_info->connect_token_sequence );

    netcode_write_bytes( &buffer, server_info->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    int i,j;

    netcode_write_uint32( &buffer, server_info->num_server_addresses );

    for ( i = 0; i < server_info->num_server_addresses; ++i )
    {
        if ( server_info->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV4 );
            for ( j = 0; j < 4; ++j )
            {
                netcode_write_uint8( &buffer, server_info->server_addresses[i].address.ipv4[j] );
            }
            netcode_write_uint16( &buffer, server_info->server_addresses[i].port );
        }
        else if ( server_info->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            netcode_write_uint8( &buffer, NETCODE_ADDRESS_IPV6 );
            for ( j = 0; j < 8; ++j )
            {
                netcode_write_uint16( &buffer, server_info->server_addresses[i].address.ipv6[j] );
            }
            netcode_write_uint16( &buffer, server_info->server_addresses[i].port );
        }
        else
        {
            assert( 0 );
        }
    }

    netcode_write_bytes( &buffer, server_info->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_write_bytes( &buffer, server_info->server_to_client_key, NETCODE_KEY_BYTES );

    assert( buffer - start <= NETCODE_SERVER_INFO_BYTES );

    memset( buffer, 0, NETCODE_SERVER_INFO_BYTES - ( buffer - start ) );

    netcode_write_uint32( &buffer, server_info->timeout_seconds );
}

int netcode_read_server_info( uint8_t * buffer, int buffer_length, struct netcode_server_info_t * server_info )
{
    assert( buffer );
    assert( server_info );

    if ( buffer_length != NETCODE_SERVER_INFO_BYTES )
    {
        printf( "read connect data: bad buffer length (%d)\n", buffer_length );
        return 0;
    }

    netcode_read_bytes( &buffer, server_info->version_info, NETCODE_VERSION_INFO_BYTES );
    if ( server_info->version_info[0]  != 'N' || 
         server_info->version_info[1]  != 'E' || 
         server_info->version_info[2]  != 'T' || 
         server_info->version_info[3]  != 'C' || 
         server_info->version_info[4]  != 'O' ||
         server_info->version_info[5]  != 'D' ||
         server_info->version_info[6]  != 'E' ||
         server_info->version_info[7]  != ' ' || 
         server_info->version_info[8]  != '1' ||
         server_info->version_info[9]  != '.' ||
         server_info->version_info[10] != '0' ||
         server_info->version_info[11] != '0' ||
         server_info->version_info[12] != '\0' )
    {
        printf( "read connect data: bad version info\n" );
        return 0;
    }

    server_info->protocol_id = netcode_read_uint64( &buffer );

    server_info->connect_token_create_timestamp = netcode_read_uint64( &buffer );

    server_info->connect_token_expire_timestamp = netcode_read_uint64( &buffer );

    server_info->connect_token_sequence = netcode_read_uint64( &buffer );

    netcode_read_bytes( &buffer, server_info->connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    server_info->num_server_addresses = netcode_read_uint32( &buffer );

    if ( server_info->num_server_addresses <= 0 || server_info->num_server_addresses > NETCODE_MAX_SERVERS_PER_CONNECT )
    {
        printf( "read connect data: bad num server addresses (%d)\n", server_info->num_server_addresses );
        return 0;
    }

    int i,j;

    for ( i = 0; i < server_info->num_server_addresses; ++i )
    {
        server_info->server_addresses[i].type = netcode_read_uint8( &buffer );

        if ( server_info->server_addresses[i].type == NETCODE_ADDRESS_IPV4 )
        {
            for ( j = 0; j < 4; ++j )
            {
                server_info->server_addresses[i].address.ipv4[j] = netcode_read_uint8( &buffer );
            }
            server_info->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else if ( server_info->server_addresses[i].type == NETCODE_ADDRESS_IPV6 )
        {
            for ( j = 0; j < 8; ++j )
            {
                server_info->server_addresses[i].address.ipv6[j] = netcode_read_uint16( &buffer );
            }
            server_info->server_addresses[i].port = netcode_read_uint16( &buffer );
        }
        else
        {
            printf( "read connect data: bad address type (%d)\n", server_info->server_addresses[i].type );
            return 0;
        }
    }

    netcode_read_bytes( &buffer, server_info->client_to_server_key, NETCODE_KEY_BYTES );

    netcode_read_bytes( &buffer, server_info->server_to_client_key, NETCODE_KEY_BYTES );

    server_info->timeout_seconds = (int) netcode_read_uint32( &buffer );
    
    return 1;
}

// ----------------------------------------------------------------
    
char * netcode_client_state_name( int client_state )
{
    switch ( client_state )
    {
        case NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED:                return "connect token expired";
        case NETCODE_CLIENT_STATE_INVALID_SERVER_INFO:                  return "invalid connect data";
        case NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT:                 return "connection timed out";
        case NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMEOUT:           return "connection request timeout";
        case NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMEOUT:          return "connection response timeout";
        case NETCODE_CLIENT_STATE_CONNECTION_CONFIRM_TIMEOUT:           return "connection confirm timeout";
        case NETCODE_CLIENT_STATE_CONNECTION_DENIED:                    return "connection denied";
        case NETCODE_CLIENT_STATE_DISCONNECTED:                         return "disconnected";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:           return "sending connection request";
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:          return "sending connection response";
        case NETCODE_CLIENT_STATE_WAITING_FOR_CONNECTION_CONFIRM:       return "waiting for connection confirm";
        case NETCODE_CLIENT_STATE_CONNECTED:                            return "connected";
        default:
            assert( 0 );
            return "???";
    }
}

struct netcode_client_t
{
	int state;
	double time;
    double connect_start_time;
	double last_packet_send_time;
	double last_packet_receive_time;
    int should_disconnect;
    int should_disconnect_state;
	uint64_t sequence;
    int client_index;
    int server_address_index;
    struct netcode_address_t server_address;
    struct netcode_server_info_t server_info;
    struct netcode_socket_t socket;
    struct netcode_packet_context_t context;
    uint64_t challenge_token_sequence;
    uint8_t challenge_token_data[NETCODE_CHALLENGE_TOKEN_BYTES];
};

struct netcode_client_t * netcode_client_create( char * address_string, double time )
{
    assert( netcode.initialized );

    struct netcode_address_t address;
    if ( !netcode_parse_address( address_string, &address ) )
    {
        printf( "error: failed to parse client address\n" );
        return NULL;
    }

    struct netcode_socket_t socket;
    if ( netcode_socket_create( &socket, &address, NETCODE_SOCKET_SNDBUF_SIZE, NETCODE_SOCKET_RCVBUF_SIZE ) != NETCODE_SOCKET_ERROR_NONE )
    {
        return NULL;
    }

	struct netcode_client_t * client = (struct netcode_client_t*) malloc( sizeof( struct netcode_client_t ) );

    if ( !client )
    {
        return NULL;
    }

    client->socket = socket;
	client->state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client->time = time;
    client->connect_start_time = 0.0;
    client->last_packet_send_time = -1000.0;
    client->last_packet_receive_time = -1000.0;
    client->should_disconnect = 0;
    client->should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
	client->sequence = 0;
    client->client_index = 0;
    client->server_address_index = 0;
    client->challenge_token_sequence = 0;
    memset( &client->server_address, 0, sizeof( struct netcode_address_t ) );
    memset( &client->server_info, 0, sizeof( struct netcode_server_info_t ) );
    memset( &client->context, 0, sizeof( struct netcode_packet_context_t ) );
    memset( client->challenge_token_data, 0, NETCODE_CHALLENGE_TOKEN_BYTES );

	return client;
}

void netcode_client_destroy( struct netcode_client_t * client )
{
    assert( client );

    netcode_client_disconnect( client );

    netcode_socket_destroy( &client->socket );

    free( client );
}

void netcode_client_set_state( struct netcode_client_t * client, int client_state )
{
    printf( "%s -> %s\n", netcode_client_state_name( client->state ), netcode_client_state_name( client_state ) );
    client->state = client_state;
}

void netcode_client_reset_before_next_connect( struct netcode_client_t * client )
{
    client->last_packet_send_time = client->time - 1.0f;
    client->last_packet_receive_time = client->time;
    client->should_disconnect = 0;
    client->should_disconnect_state = NETCODE_CLIENT_STATE_DISCONNECTED;
    client->challenge_token_sequence = 0;
    memset( client->challenge_token_data, 0, NETCODE_CHALLENGE_TOKEN_BYTES );
}

void netcode_client_reset_connection_data( struct netcode_client_t * client, int client_state )
{
    assert( client );

    client->sequence = 0;
    client->client_index = 0;
    client->connect_start_time = 0.0;
    client->server_address_index = 0;
    memset( &client->server_address, 0, sizeof( struct netcode_address_t ) );
    memset( &client->server_info, 0, sizeof( struct netcode_server_info_t ) );
    memset( &client->context, 0, sizeof( struct netcode_packet_context_t ) );

    netcode_client_set_state( client, client_state );

    netcode_client_reset_before_next_connect( client );
}

void netcode_client_disconnect_internal( struct netcode_client_t * client, int destination_state, int send_disconnect_packets );

void netcode_client_connect( struct netcode_client_t * client, uint8_t * server_info )
{
    assert( client );
    assert( server_info );

	netcode_client_disconnect( client );

    if ( !netcode_read_server_info( server_info, NETCODE_SERVER_INFO_BYTES, &client->server_info ) )
    {
        netcode_client_set_state( client, NETCODE_CLIENT_STATE_INVALID_SERVER_INFO );
        return;
    }

    client->server_address_index = 0;
    client->server_address = client->server_info.server_addresses[0];

    client->context.protocol_id = client->server_info.protocol_id;
    memcpy( client->context.read_packet_key, client->server_info.server_to_client_key, NETCODE_KEY_BYTES );
    memcpy( client->context.write_packet_key, client->server_info.client_to_server_key, NETCODE_KEY_BYTES );

	netcode_client_reset_before_next_connect( client );

    netcode_client_set_state( client, NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST );
}

void netcode_client_receive_packets( struct netcode_client_t * client )
{
	assert( client );

	(void) client;

	// todo
}

void netcode_client_send_packet_to_server_internal( struct netcode_client_t * client, void * packet )
{
    assert( client );

    uint8_t packet_data[NETCODE_MAX_PACKET_BYTES];

    client->context.current_timestamp = (uint64_t) time( NULL );

    int packet_bytes = netcode_write_packet( packet, packet_data, NETCODE_MAX_PACKET_BYTES, client->sequence, &client->context );

    printf( "packet bytes = %d\n", packet_bytes );

    assert( packet_bytes <= NETCODE_MAX_PACKET_BYTES );

    netcode_socket_send_packet( &client->socket, &client->server_address, packet_data, packet_bytes );

    client->last_packet_send_time = client->time;
}

void netcode_client_send_packets( struct netcode_client_t * client )
{
	assert( client );

    switch ( client->state )
    {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) > client->time )
                return;

            printf( "send connection request packet\n" );

            struct netcode_connection_request_packet_t packet;

            packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
            memcpy( packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
            packet.protocol_id = client->server_info.protocol_id;
            packet.connect_token_expire_timestamp = client->server_info.connect_token_expire_timestamp;
            packet.connect_token_sequence = client->server_info.connect_token_sequence;
            memcpy( packet.connect_token_data, client->server_info.connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
        break;

        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) > client->time )
                return;

            printf( "send connection response packet\n" );

            struct netcode_connection_response_packet_t packet;

            packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
            packet.challenge_token_sequence = client->challenge_token_sequence;
            memcpy( &packet.challenge_token_data, client->challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
        break;

        case NETCODE_CLIENT_STATE_CONNECTED:
        {
            if ( client->last_packet_send_time + ( 1.0 / NETCODE_PACKET_SEND_RATE ) > client->time )
                return;

            struct netcode_connection_keep_alive_packet_t packet;

            packet.packet_type = NETCODE_CONNECTION_KEEP_ALIVE_PACKET;

            netcode_client_send_packet_to_server_internal( client, &packet );
        }
        break;
        
        default:
            break;
    }
}

int netcode_client_connect_to_next_server( struct netcode_client_t * client )
{
	assert( client );

	(void) client;

    // todo
    return 0;
}

void netcode_client_advance_time( struct netcode_client_t * client, double time )
{
    assert( client );

    client->time = time;

    if ( client->state > NETCODE_CLIENT_STATE_DISCONNECTED && client->state < NETCODE_CLIENT_STATE_CONNECTED )
    {
        int connect_token_expire_seconds = ( client->server_info.connect_token_expire_timestamp - client->server_info.connect_token_create_timestamp );
        
        if ( client->connect_start_time + connect_token_expire_seconds <= client->time )
        {
            printf( "connect token expired\n" );
            netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECT_TOKEN_EXPIRED, 0 );
            return;
        }
    }

    if ( client->should_disconnect )
    {
        printf( "should disconnect -> %s\n", netcode_client_state_name( client->should_disconnect_state ) );
        if ( netcode_client_connect_to_next_server( client) )
            return;
        netcode_client_disconnect_internal( client, client->should_disconnect_state, 0 );
        return;
    }

    switch ( client->state )
    {
        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_REQUEST:
        {
            if ( client->last_packet_receive_time + client->server_info.timeout_seconds < time )
            {
                printf( "connection request timed out\n" );
                if ( netcode_client_connect_to_next_server( client ) )
                    return;
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_REQUEST_TIMEOUT, 0 );
                return;
            }
        }
        break;

        case NETCODE_CLIENT_STATE_SENDING_CONNECTION_RESPONSE:
        {
            if ( client->last_packet_receive_time + client->server_info.timeout_seconds < time )
            {
                printf( "connection response timed out\n" );
                if ( netcode_client_connect_to_next_server( client ) )
                    return;
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_RESPONSE_TIMEOUT, 0 );
                return;
            }
        }
        break;

        case NETCODE_CLIENT_STATE_WAITING_FOR_CONNECTION_CONFIRM:
        {
            if ( client->last_packet_receive_time + client->server_info.timeout_seconds < time )
            {
                printf( "connection confirm timed out\n" );
                if ( netcode_client_connect_to_next_server( client ) )
                    return;
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_CONFIRM_TIMEOUT, 0 );
                return;
            }
        }
        break;

		case NETCODE_CLIENT_STATE_CONNECTED:
        {
            if ( client->last_packet_receive_time + client->server_info.timeout_seconds < time )
            {
                printf( "connection timed out\n" );
                netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_CONNECTION_TIMED_OUT, 0 );
                return;
            }
        }
        break;

        default:
            break;
    }
}

void netcode_client_disconnect( struct netcode_client_t * client )
{
	assert( client );

    netcode_client_disconnect_internal( client, NETCODE_CLIENT_STATE_DISCONNECTED, 1 );
}

void netcode_client_disconnect_internal( struct netcode_client_t * client, int destination_state, int send_disconnect_packets )
{
    assert( destination_state <= NETCODE_CLIENT_STATE_DISCONNECTED );

    if ( client->state <= NETCODE_CLIENT_STATE_DISCONNECTED || client->state == destination_state )
        return;

    printf( "client disconnected\n" );

    if ( send_disconnect_packets && client->state > NETCODE_CLIENT_STATE_DISCONNECTED )
    {
        for ( int i = 0; i < 10; ++i )
        {
			// todo: send disconnect packets

			/*
            DisconnectPacket * packet = (DisconnectPacket*) CreatePacket( CLIENT_SERVER_PACKET_DISCONNECT );            

            if ( packet )
            {
                SendPacketToServer_Internal( packet, true );
            }
			*/
        }
    }

    netcode_client_reset_connection_data( client, destination_state );
}

int netcode_client_state( struct netcode_client_t * client )
{
    assert( client );

    return client->state;
}

// ----------------------------------------------------------------

struct netcode_server_t
{
	int dummy;
};

struct netcode_server_t * netcode_server_create( uint16_t port )
{
	(void) port;

    assert( netcode.initialized );

    struct netcode_server_t * server = (struct netcode_server_t*) malloc( sizeof( struct netcode_server_t ) );

    if ( !server )
        return NULL;

    // ...

    return server;
}

void netcode_server_start( struct netcode_server_t * server, int max_clients )
{
	(void) server;
	(void) max_clients;

	// ...
}

void netcode_server_update( struct netcode_server_t * server, double time )
{
	(void) server;
	(void) time;

	// ...
}

int netcode_server_is_client_connected( struct netcode_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...

	return 0;
}

int netcode_server_receive_packet_from_client( struct netcode_server_t * server, int client_index, uint8_t * buffer, int buffer_length )
{
	(void) server;
	(void) client_index;
	(void) buffer;
	(void) buffer_length;

	// ...

	return 0;
}

void netcode_server_send_packet_to_client( struct netcode_server_t * server, int client_index, uint8_t * packet_data, int packet_size )
{
	(void) server;
	(void) client_index;
	(void) packet_data;
	(void) packet_size;

	// ...
}

void netcode_server_disconnect_client( struct netcode_server_t * server, int client_index )
{
	(void) server;
	(void) client_index;

	// ...
}

void netcode_server_disconnect_all_clients( struct netcode_server_t * server )
{
	(void) server;

	// ...
}

void netcode_server_stop( struct netcode_server_t * server )
{
	(void) server;

	// ...
}

void netcode_server_destroy( struct netcode_server_t * server )
{
    assert( server );

	(void) server;

	// ...

    free( server );
}

// ----------------------------------------------------------------

int netcode_generate_server_info( int num_server_addresses, char ** server_addresses, int expire_seconds, uint64_t client_id, uint64_t protocol_id, uint8_t * private_key, uint8_t * output_buffer )
{
    assert( num_server_addresses > 0 );
    assert( num_server_addresses <= NETCODE_MAX_SERVERS_PER_CONNECT );
    assert( server_addresses );
    assert( private_key );
    assert( output_buffer );

    // parse server addresses

    struct netcode_address_t parsed_server_addresses[NETCODE_MAX_SERVERS_PER_CONNECT];

    for ( int i = 0; i < num_server_addresses; ++i )
    {
        if ( !netcode_parse_address( server_addresses[i], &parsed_server_addresses[i] ) )
            return 0;
    }

    // generate a connect token

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t connect_token;

    netcode_generate_connect_token( &connect_token, client_id, num_server_addresses, parsed_server_addresses, user_data );

    // write it to a buffer

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &connect_token, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint64_t create_timestamp = time( NULL );
    uint64_t expire_timestamp = create_timestamp + expire_seconds;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key( key );    

    if ( !netcode_encrypt_connect_token( connect_token_data, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, protocol_id, expire_timestamp, sequence, key ) )
        return 0;

    // wrap a server info around the connect token

    struct netcode_server_info_t server_info;

    memcpy( server_info.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    server_info.protocol_id = protocol_id;
    server_info.connect_token_create_timestamp = create_timestamp;
    server_info.connect_token_expire_timestamp = expire_timestamp;
    server_info.connect_token_sequence = sequence;
    memcpy( server_info.connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );
    server_info.num_server_addresses = num_server_addresses;
    for ( int i = 0; i < num_server_addresses; ++i )
        server_info.server_addresses[i] = parsed_server_addresses[i];
    memcpy( server_info.client_to_server_key, connect_token.client_to_server_key, NETCODE_KEY_BYTES );
    memcpy( server_info.server_to_client_key, connect_token.server_to_client_key, NETCODE_KEY_BYTES );
    server_info.timeout_seconds = NETCODE_TIMEOUT_SECONDS;

    // write the server info to the output buffer

    netcode_write_server_info( &server_info, output_buffer, NETCODE_SERVER_INFO_BYTES );

    return 1;
}

// ---------------------------------------------------------------

#define NETCODE_TEST 1

#if NETCODE_TEST

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <time.h>

static void check_handler( char * condition, 
                           char * function,
                           char * file,
                           int line )
{
    printf( "check failed: ( %s ), function %s, file %s, line %d\n", condition, function, file, line );
#ifndef NDEBUG
    #if defined( __GNUC__ )
        __builtin_trap();
    #elif defined( _MSC_VER )
        __debugbreak();
    #endif
#endif
    exit( 1 );
}

#define check( condition )                                                                      \
do                                                                                              \
{                                                                                               \
    if ( !(condition) )                                                                         \
    {                                                                                           \
        check_handler( #condition, (char*) __FUNCTION__, (char*) __FILE__, __LINE__ );          \
    }                                                                                           \
} while(0)

static void test_endian()
{
    uint32_t value = 0x11223344;

    char * bytes = (char*) &value;

#if NETCODE_LITTLE_ENDIAN

    check( bytes[0] == 0x44 );
    check( bytes[1] == 0x33 );
    check( bytes[2] == 0x22 );
    check( bytes[3] == 0x11 );

#else // #if NETCODE_LITTLE_ENDIAN

    check( bytes[3] == 0x44 );
    check( bytes[2] == 0x33 );
    check( bytes[1] == 0x22 );
    check( bytes[0] == 0x11 );

#endif // #if NETCODE_LITTLE_ENDIAN
}

static void test_sequence()
{
    check( netcode_sequence_number_bytes_required( 0 ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x11 ) == 1 );
    check( netcode_sequence_number_bytes_required( 0x1122 ) == 2 );
    check( netcode_sequence_number_bytes_required( 0x112233 ) == 3 );
    check( netcode_sequence_number_bytes_required( 0x11223344 ) == 4 );
    check( netcode_sequence_number_bytes_required( 0x1122334455 ) == 5 );
    check( netcode_sequence_number_bytes_required( 0x112233445566 ) == 6 );
    check( netcode_sequence_number_bytes_required( 0x11223344556677 ) == 7 );
    check( netcode_sequence_number_bytes_required( 0x1122334455667788 ) == 8 );
}

static void test_address()
{
    {
        struct netcode_address_t address;
        check( netcode_parse_address( "", &address ) == 0 );
        check( netcode_parse_address( "[", &address ) == 0 );
        check( netcode_parse_address( "[]", &address ) == 0 );
        check( netcode_parse_address( "[]:", &address ) == 0 );
        check( netcode_parse_address( ":", &address ) == 0 );
        check( netcode_parse_address( "1", &address ) == 0 );
        check( netcode_parse_address( "12", &address ) == 0 );
        check( netcode_parse_address( "123", &address ) == 0 );
        check( netcode_parse_address( "1234", &address ) == 0 );
        check( netcode_parse_address( "1234.0.12313.0000", &address ) == 0 );
        check( netcode_parse_address( "1234.0.12313.0000.0.0.0.0.0", &address ) == 0 );
        check( netcode_parse_address( "1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131:1312313:123131", &address ) == 0 );
        check( netcode_parse_address( ".", &address ) == 0 );
        check( netcode_parse_address( "..", &address ) == 0 );
        check( netcode_parse_address( "...", &address ) == 0 );
        check( netcode_parse_address( "....", &address ) == 0 );
        check( netcode_parse_address( ".....", &address ) == 0 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "107.77.207.77", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 0 );
        check( address.address.ipv4[0] == 107 );
        check( address.address.ipv4[1] == 77 );
        check( address.address.ipv4[2] == 207 );
        check( address.address.ipv4[3] == 77 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "127.0.0.1", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 0 );
        check( address.address.ipv4[0] == 127 );
        check( address.address.ipv4[1] == 0 );
        check( address.address.ipv4[2] == 0 );
        check( address.address.ipv4[3] == 1 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "107.77.207.77:40000", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 40000 );
        check( address.address.ipv4[0] == 107 );
        check( address.address.ipv4[1] == 77 );
        check( address.address.ipv4[2] == 207 );
        check( address.address.ipv4[3] == 77 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "127.0.0.1:40000", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV4 );
        check( address.port == 40000 );
        check( address.address.ipv4[0] == 127 );
        check( address.address.ipv4[1] == 0 );
        check( address.address.ipv4[2] == 0 );
        check( address.address.ipv4[3] == 1 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "fe80::202:b3ff:fe1e:8329", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.address.ipv6[0] == 0xfe80 );
        check( address.address.ipv6[1] == 0x0000 );
        check( address.address.ipv6[2] == 0x0000 );
        check( address.address.ipv6[3] == 0x0000 );
        check( address.address.ipv6[4] == 0x0202 );
        check( address.address.ipv6[5] == 0xb3ff );
        check( address.address.ipv6[6] == 0xfe1e );
        check( address.address.ipv6[7] == 0x8329 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "::1", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 0 );
        check( address.address.ipv6[0] == 0x0000 );
        check( address.address.ipv6[1] == 0x0000 );
        check( address.address.ipv6[2] == 0x0000 );
        check( address.address.ipv6[3] == 0x0000 );
        check( address.address.ipv6[4] == 0x0000 );
        check( address.address.ipv6[5] == 0x0000 );
        check( address.address.ipv6[6] == 0x0000 );
        check( address.address.ipv6[7] == 0x0001 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[fe80::202:b3ff:fe1e:8329]:40000", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 40000 );
        check( address.address.ipv6[0] == 0xfe80 );
        check( address.address.ipv6[1] == 0x0000 );
        check( address.address.ipv6[2] == 0x0000 );
        check( address.address.ipv6[3] == 0x0000 );
        check( address.address.ipv6[4] == 0x0202 );
        check( address.address.ipv6[5] == 0xb3ff );
        check( address.address.ipv6[6] == 0xfe1e );
        check( address.address.ipv6[7] == 0x8329 );
    }

    {
        struct netcode_address_t address;
        check( netcode_parse_address( "[::1]:40000", &address ) );
        check( address.type == NETCODE_ADDRESS_IPV6 );
        check( address.port == 40000 );
        check( address.address.ipv6[0] == 0x0000 );
        check( address.address.ipv6[1] == 0x0000 );
        check( address.address.ipv6[2] == 0x0000 );
        check( address.address.ipv6[3] == 0x0000 );
        check( address.address.ipv6[4] == 0x0000 );
        check( address.address.ipv6[5] == 0x0000 );
        check( address.address.ipv6[6] == 0x0000 );
        check( address.address.ipv6[7] == 0x0001 );
    }
}

#define TEST_PROTOCOL_ID    0x1122334455667788LL
#define TEST_CLIENT_ID      0x1LL
#define TEST_SERVER_PORT    40000

static void test_connect_token()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.address.ipv4[0] = 127;
    server_address.address.ipv4[1] = 0;
    server_address.address.ipv4[2] = 0;
    server_address.address.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t input_token;

    netcode_generate_connect_token( &input_token, TEST_CLIENT_ID, 1, &server_address, user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( memcmp( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) == 0 );
    check( netcode_address_equal( &input_token.server_addresses[0], &server_address ) );

    // write it to a buffer

    uint8_t buffer[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &input_token, buffer, NETCODE_CONNECT_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint64_t expire_timestamp = time( NULL ) + 30;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key( key );    

    check( netcode_encrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // decrypt the buffer

    check( netcode_decrypt_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // read the connect token back in

    struct netcode_connect_token_t output_token;

    check( netcode_read_connect_token( buffer, NETCODE_CONNECT_TOKEN_BYTES, &output_token ) == 1 );

	// make sure that everything matches the original connect token

    check( output_token.client_id == input_token.client_id );
    check( output_token.num_server_addresses == input_token.num_server_addresses );
    check( netcode_address_equal( &output_token.server_addresses[0], &input_token.server_addresses[0] ) );
    check( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.user_data, input_token.user_data, NETCODE_USER_DATA_BYTES ) == 0 );
}

static void test_challenge_token()
{
    // generate a challenge token

    struct netcode_challenge_token_t input_token;

    input_token.client_id = TEST_CLIENT_ID;
	netcode_random_bytes( input_token.connect_token_mac, NETCODE_MAC_BYTES );
	netcode_generate_key( input_token.client_to_server_key );
	netcode_generate_key( input_token.server_to_client_key );

    // write it to a buffer

    uint8_t buffer[NETCODE_CHALLENGE_TOKEN_BYTES];

    netcode_write_challenge_token( &input_token, buffer, NETCODE_CHALLENGE_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint8_t key[NETCODE_KEY_BYTES]; 
	netcode_generate_key( key );    

    check( netcode_encrypt_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key ) == 1 );

    // decrypt the buffer

    check( netcode_decrypt_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, sequence, key ) == 1 );

    // read the challenge token back in

    struct netcode_challenge_token_t output_token;

    check( netcode_read_challenge_token( buffer, NETCODE_CHALLENGE_TOKEN_BYTES, &output_token ) == 1 );

	// make sure that everything matches the original challenge token

    check( output_token.client_id == input_token.client_id );
    check( memcmp( output_token.connect_token_mac, input_token.connect_token_mac, NETCODE_MAC_BYTES ) == 0 );
    check( memcmp( output_token.client_to_server_key, input_token.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_token.server_to_client_key, input_token.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
}

static void test_connection_request_packet()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.address.ipv4[0] = 127;
    server_address.address.ipv4[1] = 0;
    server_address.address.ipv4[2] = 0;
    server_address.address.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t input_token;

    netcode_generate_connect_token( &input_token, TEST_CLIENT_ID, 1, &server_address, user_data );

    check( input_token.client_id == TEST_CLIENT_ID );
    check( input_token.num_server_addresses == 1 );
    check( memcmp( input_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) == 0 );
    check( netcode_address_equal( &input_token.server_addresses[0], &server_address ) );

    // write the conect token to a buffer (non-encrypted)

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &input_token, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    // copy to a second buffer then encrypt it in place (we need the unencrypted token for verification later on)

    uint8_t encrypted_connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    memcpy( encrypted_connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    uint64_t connect_token_sequence = 1000;
    uint64_t connect_token_expire_timestamp = time( NULL ) + 30;
    uint8_t connect_token_key[NETCODE_KEY_BYTES];
    netcode_generate_key( connect_token_key );

    check( netcode_encrypt_connect_token( encrypted_connect_token_data, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, connect_token_expire_timestamp, connect_token_sequence, connect_token_key ) == 1 );

    // setup a connection request packet wrapping the encrypted connect token

    struct netcode_connection_request_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_REQUEST_PACKET;
    memcpy( input_packet.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    input_packet.protocol_id = TEST_PROTOCOL_ID;
    input_packet.connect_token_expire_timestamp = connect_token_expire_timestamp;
    input_packet.connect_token_sequence = connect_token_sequence;
    memcpy( input_packet.connect_token_data, encrypted_connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

	// write the connection request packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
	context.protocol_id = TEST_PROTOCOL_ID;
	context.current_timestamp = (uint64_t) time( NULL );
	memcpy( context.connect_token_key, connect_token_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

	// read the connection request packet back in from the buffer (the connect token data is decrypted as part of the read packet validation)

	uint64_t sequence = 1000;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_request_packet_t * output_packet = (struct netcode_connection_request_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

	// make sure the read packet matches what was written
	
    check( output_packet->packet_type == NETCODE_CONNECTION_REQUEST_PACKET );
    check( memcmp( output_packet->version_info, input_packet.version_info, NETCODE_VERSION_INFO_BYTES ) == 0 );
    check( output_packet->protocol_id == input_packet.protocol_id );
    check( output_packet->connect_token_expire_timestamp == input_packet.connect_token_expire_timestamp );
	check( output_packet->connect_token_sequence == input_packet.connect_token_sequence );
    check( memcmp( output_packet->connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES ) == 0 );

    free( output_packet );
}

void test_connection_denied_packet()
{
    // setup a connection denied packet

    struct netcode_connection_denied_packet_t input_packet;

	input_packet.packet_type = NETCODE_CONNECTION_DENIED_PACKET;

	// write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
	context.protocol_id = TEST_PROTOCOL_ID;
	netcode_generate_key( context.write_packet_key );
	memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

	// read the packet back in from the buffer

	uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_denied_packet_t * output_packet = (struct netcode_connection_denied_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

	// make sure the read packet matches what was written
	
    check( output_packet->packet_type == NETCODE_CONNECTION_DENIED_PACKET );

    free( output_packet );
}

void test_connection_challenge_packet()
{
    // setup a connection challenge packet

    struct netcode_connection_challenge_packet_t input_packet;

	input_packet.packet_type = NETCODE_CONNECTION_CHALLENGE_PACKET;
	input_packet.challenge_token_sequence = 0;
	netcode_random_bytes( input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

	// write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
	context.protocol_id = TEST_PROTOCOL_ID;
	netcode_generate_key( context.write_packet_key );
	memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

	// read the packet back in from the buffer

	uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_challenge_packet_t * output_packet = (struct netcode_connection_challenge_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

	// make sure the read packet packet matches what was written
	
    check( output_packet->packet_type == NETCODE_CONNECTION_CHALLENGE_PACKET );
	check( output_packet->challenge_token_sequence == input_packet.challenge_token_sequence );
	check( memcmp( output_packet->challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES ) == 0 );

    free( output_packet );
}

void test_connection_response_packet()
{
    // setup a connection response packet

    struct netcode_connection_response_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_RESPONSE_PACKET;
    input_packet.challenge_token_sequence = 0;
    netcode_random_bytes( input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES );

    // write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
    context.protocol_id = TEST_PROTOCOL_ID;
    netcode_generate_key( context.write_packet_key );
    memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_response_packet_t * output_packet = (struct netcode_connection_response_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_RESPONSE_PACKET );
    check( output_packet->challenge_token_sequence == input_packet.challenge_token_sequence );
    check( memcmp( output_packet->challenge_token_data, input_packet.challenge_token_data, NETCODE_CHALLENGE_TOKEN_BYTES ) == 0 );

    free( output_packet );
}

void test_connection_confirm_packet()
{
    // setup a connection confirm packet

    struct netcode_connection_confirm_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_CONFIRM_PACKET;
    input_packet.client_index = 10;

    // write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
    context.protocol_id = TEST_PROTOCOL_ID;
    netcode_generate_key( context.write_packet_key );
    memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );
    
    struct netcode_connection_confirm_packet_t * output_packet = (struct netcode_connection_confirm_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_CONFIRM_PACKET );
    check( output_packet->client_index == input_packet.client_index );

    free( output_packet );
}

void test_connection_payload_packet()
{
    // setup a connection payload packet

    struct netcode_connection_payload_packet_t * input_packet = netcode_create_payload_packet( NETCODE_MAX_PAYLOAD_BYTES );

	check( input_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
	check( input_packet->payload_bytes == NETCODE_MAX_PAYLOAD_BYTES );

	netcode_random_bytes( input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES );
    
    // write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
    context.protocol_id = TEST_PROTOCOL_ID;
    netcode_generate_key( context.write_packet_key );
    memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_payload_packet_t * output_packet = (struct netcode_connection_payload_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_PAYLOAD_PACKET );
	check( output_packet->payload_bytes == input_packet->payload_bytes );
	check( memcmp( output_packet->payload_data, input_packet->payload_data, NETCODE_MAX_PAYLOAD_BYTES ) == 0 );

	free( input_packet );
    free( output_packet );
}

void test_connection_disconnect_packet()
{
    // setup a connection disconnect packet

    struct netcode_connection_disconnect_packet_t input_packet;

    input_packet.packet_type = NETCODE_CONNECTION_DISCONNECT_PACKET;

    // write the packet to a buffer

    uint8_t buffer[2048];

    struct netcode_packet_context_t context;
    memset( &context, 0, sizeof( context ) );
    context.protocol_id = TEST_PROTOCOL_ID;
    netcode_generate_key( context.write_packet_key );
    memcpy( context.read_packet_key, context.write_packet_key, NETCODE_KEY_BYTES );

    int bytes_written = netcode_write_packet( &input_packet, buffer, sizeof( buffer ), 1000, &context );

    check( bytes_written > 0 );

    // read the packet back in from the buffer

    uint64_t sequence;

    uint8_t allowed_packet_types[NETCODE_CONNECTION_NUM_PACKETS];
    memset( allowed_packet_types, 1, sizeof( allowed_packet_types ) );

    struct netcode_connection_disconnect_packet_t * output_packet = (struct netcode_connection_disconnect_packet_t*) netcode_read_packet( buffer, bytes_written, &sequence, &context, allowed_packet_types );

    check( output_packet );

    // make sure the read packet matches what was written
    
    check( output_packet->packet_type == NETCODE_CONNECTION_DISCONNECT_PACKET );

    free( output_packet );
}

void test_server_info()
{
    // generate a connect token

    struct netcode_address_t server_address;
    server_address.type = NETCODE_ADDRESS_IPV4;
    server_address.address.ipv4[0] = 127;
    server_address.address.ipv4[1] = 0;
    server_address.address.ipv4[2] = 0;
    server_address.address.ipv4[3] = 1;
    server_address.port = TEST_SERVER_PORT;

    uint8_t user_data[NETCODE_USER_DATA_BYTES];
    netcode_random_bytes( user_data, NETCODE_USER_DATA_BYTES );

    struct netcode_connect_token_t connect_token;

    netcode_generate_connect_token( &connect_token, TEST_CLIENT_ID, 1, &server_address, user_data );

    check( connect_token.client_id == TEST_CLIENT_ID );
    check( connect_token.num_server_addresses == 1 );
    check( memcmp( connect_token.user_data, user_data, NETCODE_USER_DATA_BYTES ) == 0 );
    check( netcode_address_equal( &connect_token.server_addresses[0], &server_address ) );

    // write it to a buffer

    uint8_t connect_token_data[NETCODE_CONNECT_TOKEN_BYTES];

    netcode_write_connect_token( &connect_token, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );

    // encrypt the buffer

    uint64_t sequence = 1000;
    uint64_t create_timestamp = time( NULL );
    uint64_t expire_timestamp = create_timestamp + 30;
    uint8_t key[NETCODE_KEY_BYTES];
    netcode_generate_key( key );    

    check( netcode_encrypt_connect_token( connect_token_data, NETCODE_CONNECT_TOKEN_BYTES, NETCODE_VERSION_INFO, TEST_PROTOCOL_ID, expire_timestamp, sequence, key ) == 1 );

    // wrap the connect token inside a server info

    struct netcode_server_info_t input_server_info;

    memcpy( input_server_info.version_info, NETCODE_VERSION_INFO, NETCODE_VERSION_INFO_BYTES );
    input_server_info.protocol_id = TEST_PROTOCOL_ID;
    input_server_info.connect_token_create_timestamp = create_timestamp;
    input_server_info.connect_token_expire_timestamp = expire_timestamp;
    input_server_info.connect_token_sequence = sequence;
    memcpy( input_server_info.connect_token_data, connect_token_data, NETCODE_CONNECT_TOKEN_BYTES );
    input_server_info.num_server_addresses = 1;
    input_server_info.server_addresses[0] = server_address;
    memcpy( input_server_info.client_to_server_key, connect_token.client_to_server_key, NETCODE_KEY_BYTES );
    memcpy( input_server_info.server_to_client_key, connect_token.server_to_client_key, NETCODE_KEY_BYTES );
    input_server_info.timeout_seconds = NETCODE_TIMEOUT_SECONDS;

    // write the server info to a buffer

    uint8_t buffer[NETCODE_SERVER_INFO_BYTES];

    netcode_write_server_info( &input_server_info, buffer, NETCODE_SERVER_INFO_BYTES );

    // read the buffer back in

    struct netcode_server_info_t output_server_info;

    check( netcode_read_server_info( buffer, NETCODE_SERVER_INFO_BYTES, &output_server_info ) == 1 );

    // make sure the server info matches what was written

    check( memcmp( output_server_info.version_info, input_server_info.version_info, NETCODE_VERSION_INFO_BYTES ) == 0 );
    check( output_server_info.protocol_id == input_server_info.protocol_id );
    check( output_server_info.connect_token_create_timestamp == input_server_info.connect_token_create_timestamp );
    check( output_server_info.connect_token_expire_timestamp == input_server_info.connect_token_expire_timestamp );
    check( output_server_info.connect_token_sequence == input_server_info.connect_token_sequence );
    check( memcmp( output_server_info.connect_token_data, input_server_info.connect_token_data, NETCODE_CONNECT_TOKEN_BYTES ) == 0 );
    check( output_server_info.num_server_addresses == input_server_info.num_server_addresses );
    check( netcode_address_equal( &output_server_info.server_addresses[0], &input_server_info.server_addresses[0] ) );
    check( memcmp( output_server_info.client_to_server_key, input_server_info.client_to_server_key, NETCODE_KEY_BYTES ) == 0 );
    check( memcmp( output_server_info.server_to_client_key, input_server_info.server_to_client_key, NETCODE_KEY_BYTES ) == 0 );
    check( output_server_info.timeout_seconds == input_server_info.timeout_seconds );
}

#define RUN_TEST( test_function )                                           \
    do                                                                      \
    {                                                                       \
        printf( #test_function "\n" );                                      \
        test_function();                                                    \
    }                                                                       \
    while (0)

void netcode_test()
{
    RUN_TEST( test_endian );
    RUN_TEST( test_address );
    RUN_TEST( test_sequence );
    RUN_TEST( test_connect_token );
    RUN_TEST( test_challenge_token );
    RUN_TEST( test_connection_request_packet );
    RUN_TEST( test_connection_denied_packet );
    RUN_TEST( test_connection_challenge_packet );
    RUN_TEST( test_connection_response_packet );
    RUN_TEST( test_connection_confirm_packet );
    RUN_TEST( test_connection_payload_packet );
    RUN_TEST( test_connection_disconnect_packet );
    RUN_TEST( test_server_info );
}

#endif // #if NETCODE_TEST
