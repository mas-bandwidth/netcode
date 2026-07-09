/*
    netcode fuzz harness support

    Each harness compiles netcode.c directly into itself so it can reach internal
    functions, and defines LLVMFuzzerTestOneInput.

    Built with -fsanitize=fuzzer this is a libFuzzer target. Compilers without
    libFuzzer (AppleClang, GCC, MSVC) define NETCODE_FUZZ_STANDALONE instead, which
    provides a main() that replays input files given on the command line, so
    harnesses always compile everywhere and crashes can be reproduced from files.
*/

#ifndef NETCODE_FUZZ_H
#define NETCODE_FUZZ_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size );

#define FUZZ_CHECK( condition )                                                             \
do                                                                                          \
{                                                                                           \
    if ( !(condition) )                                                                     \
    {                                                                                       \
        fprintf( stderr, "fuzz check failed: ( %s ), file %s, line %d\n",                   \
            #condition, __FILE__, __LINE__ );                                               \
        abort();                                                                            \
    }                                                                                       \
} while(0)

// read little endian values out of the fuzz input, returning 0 once it runs dry

struct fuzz_input_t
{
    const uint8_t * data;
    size_t size;
    size_t offset;
};

static uint8_t fuzz_read_u8( struct fuzz_input_t * in )
{
    if ( in->offset >= in->size )
        return 0;
    return in->data[in->offset++];
}

static uint16_t fuzz_read_u16( struct fuzz_input_t * in )
{
    uint16_t value = fuzz_read_u8( in );
    value |= ( (uint16_t) fuzz_read_u8( in ) ) << 8;
    return value;
}

static uint64_t fuzz_read_u64( struct fuzz_input_t * in )
{
    uint64_t value = 0;
    int i;
    for ( i = 0; i < 8; i++ )
    {
        value |= ( (uint64_t) fuzz_read_u8( in ) ) << ( 8 * i );
    }
    return value;
}

static void fuzz_read_bytes( struct fuzz_input_t * in, uint8_t * output, size_t bytes )
{
    size_t i;
    for ( i = 0; i < bytes; i++ )
    {
        output[i] = fuzz_read_u8( in );
    }
}

#ifdef NETCODE_FUZZ_STANDALONE

int main( int argc, char ** argv )
{
    int i;
    for ( i = 1; i < argc; i++ )
    {
        FILE * file = fopen( argv[i], "rb" );
        if ( !file )
        {
            fprintf( stderr, "could not open %s\n", argv[i] );
            return 1;
        }
        fseek( file, 0, SEEK_END );
        long file_size = ftell( file );
        fseek( file, 0, SEEK_SET );
        uint8_t * data = (uint8_t*) malloc( file_size > 0 ? (size_t) file_size : 1 );
        size_t bytes_read = fread( data, 1, (size_t) file_size, file );
        fclose( file );
        LLVMFuzzerTestOneInput( data, bytes_read );
        free( data );
        printf( "%s: ok\n", argv[i] );
    }
    return 0;
}

#endif // #ifdef NETCODE_FUZZ_STANDALONE

#endif // #ifndef NETCODE_FUZZ_H
