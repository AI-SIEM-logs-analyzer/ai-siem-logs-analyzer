package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class IpLiteralsTest {

    // Every literal accepted here is round-tripped against InetAddress.getByName below. That is
    // safe: a *valid* literal never triggers a DNS lookup, only an unparsable one does. The
    // round-trip is what guards the hand-written IPv6 parser against mis-parsing a byte out of
    // place - it does not, by itself, prove that DNS was never reached (the other tests do that).
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
        // These are exactly the shapes that used to fall through to the JDK's DNS fallback: a colon
        // alone is not proof of IPv6 shape, and the guard must reject them without ever calling
        // InetAddress.getByName.
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
        // Decision: leading zeroes are rejected rather than read as decimal. Some parsers read a
        // leading zero as octal, so one spelling must not silently mean two different addresses -
        // the same reasoning IpFilter's own IPv4 pattern documents for the search filter.
        assertTrue(IpLiterals.parse("01.2.3.4").isEmpty());
    }

    @Test
    void rejectsIpv6ZoneIndices() {
        // Decision: a zone index is rejected rather than stripped. It names an interface on the
        // machine doing the parsing, which means nothing to an address read out of a log line or
        // matched against a configured range - IpFilter takes the same position for its filter.
        assertTrue(IpLiterals.parse("fe80::1%eth0").isEmpty());
    }

    @Test
    void blankAndNullAreEmpty() {
        assertTrue(IpLiterals.parse("  ").isEmpty());
        assertTrue(IpLiterals.parse(null).isEmpty());
    }
}
