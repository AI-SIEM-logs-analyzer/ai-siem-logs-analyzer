package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class IpLiteralsTest {

    private static final List<String> VALID_LITERALS =
            List.of(
                    "8.8.8.8",
                    "0.0.0.0",
                    "255.255.255.255",
                    "2001:db8::1",
                    "2001:4860:4860::8888",
                    "::1",
                    "::",
                    "::ffff:192.0.2.1",
                    "fe80::1");

    @Test
    void acceptsValidLiteralsAndMatchesGetByNameBytes() throws Exception {
        for (String literal : VALID_LITERALS) {
            Optional<InetAddress> parsed = IpLiterals.parse(literal);
            assertTrue(parsed.isPresent(), literal + " should parse");
            byte[] reference = InetAddress.getByName(literal).getAddress();
            assertArrayEquals(reference, parsed.get().getAddress(), literal + " byte mismatch");
        }
    }

    @Test
    void rejectsColonBearingStringsThatAreNotValidIpv6() {

        assertTrue(IpLiterals.parse("host:8080").isEmpty());
        assertTrue(IpLiterals.parse("google.com:80").isEmpty());
        assertTrue(IpLiterals.parse("zzz:1").isEmpty());
        assertTrue(IpLiterals.parse("example.com").isEmpty());
    }

    @Test
    void rejectsOutOfRangeAndMalformedIpv4() {
        assertTrue(IpLiterals.parse("999.1.1.1").isEmpty());
        assertTrue(IpLiterals.parse("1.2.3.4.5").isEmpty());
        assertTrue(IpLiterals.parse("1.2.3").isEmpty());
    }

    @Test
    void rejectsLeadingZeroesInIpv4Octets() {

        assertTrue(IpLiterals.parse("01.2.3.4").isEmpty());
    }

    @Test
    void rejectsIpv6ZoneIndices() {

        assertTrue(IpLiterals.parse("fe80::1%eth0").isEmpty());
    }

    @Test
    void blankAndNullAreEmpty() {
        assertTrue(IpLiterals.parse("  ").isEmpty());
        assertTrue(IpLiterals.parse(null).isEmpty());
    }
}
