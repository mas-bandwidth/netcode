/*
    fuzz netcode_parse_address.

    address strings come from the game's backend via connect tokens and from
    application code, and the parser does in-place string surgery with a safety
    margin, so it deserves adversarial input.

    also checks the round trip property: any address that parses must survive
    netcode_address_to_string -> netcode_parse_address unchanged.
*/

#include "netcode.c"
#include "fuzz.h"

#define FUZZ_MAX_ADDRESS_LENGTH 4096

int LLVMFuzzerTestOneInput( const uint8_t * data, size_t size )
{
    char address_string[FUZZ_MAX_ADDRESS_LENGTH];

    size_t length = size;
    if ( length > FUZZ_MAX_ADDRESS_LENGTH - 1 )
        length = FUZZ_MAX_ADDRESS_LENGTH - 1;

    memcpy( address_string, data, length );
    address_string[length] = '\0';

    struct netcode_address_t address;
    if ( netcode_parse_address( address_string, &address ) != NETCODE_OK )
        return 0;

    FUZZ_CHECK( address.type == NETCODE_ADDRESS_IPV4 || address.type == NETCODE_ADDRESS_IPV6 );

    char round_trip_string[NETCODE_MAX_ADDRESS_STRING_LENGTH];
    netcode_address_to_string( &address, round_trip_string );

    struct netcode_address_t round_trip_address;
    FUZZ_CHECK( netcode_parse_address( round_trip_string, &round_trip_address ) == NETCODE_OK );
    FUZZ_CHECK( netcode_address_equal( &address, &round_trip_address ) );

    return 0;
}
