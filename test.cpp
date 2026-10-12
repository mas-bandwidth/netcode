/*
    netcode

    Copyright © 2017 - 2026, Más Bandwidth LLC

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

#define NETCODE_ENABLE_TESTS 1

#include "netcode.h"
#include "netcode.c"
#include <stdio.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>

static float fp_bits_to_float( uint32_t bits )
{
    float value;
    memcpy( &value, &bits, sizeof( value ) );
    return value;
}

static uint32_t fp_float_to_bits( float value )
{
    uint32_t bits;
    memcpy( &bits, &value, sizeof( bits ) );
    return bits;
}

static double fp_bits_to_double( uint64_t bits )
{
    double value;
    memcpy( &value, &bits, sizeof( value ) );
    return value;
}

static uint64_t fp_double_to_bits( double value )
{
    uint64_t bits;
    memcpy( &bits, &value, sizeof( bits ) );
    return bits;
}

// test_fp_contract_off: red-first canary for the -ffp-contract=off / /fp:precise
// flag CMakeLists.txt sets directory-wide (CMakeLists.txt:59-65). It is built to
// go red if that flag is dropped: with floating-point contraction enabled (GCC's
// -ffp-contract=fast, clang's default =on, MSVC's /fp:fast) the compiler fuses
// a * b + c into a single FMA with one rounding, and the expressions below produce
// a different bit pattern. With contraction off each product rounds separately and
// the result is exactly zero.
//
// The inputs are read through volatile so the compiler cannot fold them to the
// expected constants at -O2; without that the canary would pass whatever the flag
// says. The values differ by one ULP between the fused and unfused paths:
//   a = b = 1 + 2^-12, c = -(1 + 2^-11)
//     unfused: (1 + 2^-11) + c = 0                          -> 0x00000000
//     fused:   1 + 2^-11 + 2^-24 - 1 - 2^-11 = 2^-24        -> 0x33800000
//   a = b = 1 + 2^-27, c = -(1 + 2^-26)
//     unfused: (1 + 2^-26) + c = 0                          -> 0x0000000000000000
//     fused:   2^-54                                        -> 0x3C90000000000000
//
// FMA is in the aarch64 baseline and absent from x86-64 unless -mfma is passed,
// so on the plain x86-64 CI legs (ubuntu-24.04 x64, windows-2022) this test cannot
// go red whatever the flag says. The macos-15 (Apple Silicon) and ubuntu-24.04-arm
// legs are where it has teeth -- which is why the flag is directory-wide in
// CMakeLists.txt: every leg builds through that file.
static void test_fp_contract_off()
{
    {
        volatile float a = fp_bits_to_float( 0x3F800800u );   // 1 + 2^-12
        volatile float b = fp_bits_to_float( 0x3F800800u );   // 1 + 2^-12
        volatile float c = fp_bits_to_float( 0xBF801000u );   // -(1 + 2^-11)

        float sum = a * b + c;

        check( fp_float_to_bits( sum ) == 0x00000000u );
    }
    {
        volatile double a = fp_bits_to_double( 0x3FF0000002000000ull );  // 1 + 2^-27
        volatile double b = fp_bits_to_double( 0x3FF0000002000000ull );  // 1 + 2^-27
        volatile double c = fp_bits_to_double( 0xBFF0000004000000ull );  // -(1 + 2^-26)

        double sum = a * b + c;

        check( fp_double_to_bits( sum ) == 0x0000000000000000ull );
    }
}

int main( int argc, char ** argv )
{
	(void) argc;
	(void) argv;

    printf( "\n" );

    test_fp_contract_off();

	netcode_init();

    netcode_test();

    netcode_term();
	
    printf( "\n*** ALL TESTS PASSED ***\n\n" );

    return 0;
}
