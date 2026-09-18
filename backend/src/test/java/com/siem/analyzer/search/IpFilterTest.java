package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class IpFilterTest {

    @Test
    void acceptsAnIpv4Address() {
        assertEquals("203.0.113.7", IpFilter.parse("203.0.113.7").value());
    }

    @Test
    void acceptsAnIpv4Range() {
        assertEquals("10.0.0.0/8", IpFilter.parse("10.0.0.0/8").value());
    }

    @Test
    void acceptsAnIpv6AddressAndRange() {
        assertEquals("::1", IpFilter.parse("::1").value());
        assertEquals("2001:db8::/32", IpFilter.parse("2001:db8::/32").value());
    }

    @Test
    void trimsSurroundingWhitespace() {
        assertEquals("192.168.1.1", IpFilter.parse("  192.168.1.1 ").value());
    }

    @Test
    void refusesAnOctetOutOfRange() {
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("256.1.1.1"));
        assertTrue(exception.getMessage().contains("256.1.1.1"));
    }

    @Test
    void refusesTheShortenedIpv4FormsTheJdkWouldAccept() {
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("127.1"));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("0x7f.0.0.1"));
    }

    @Test
    void refusesAHostName() {
        // A name would be resolved, which turns a search parameter into a DNS query.
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("example.com"));
    }

    @Test
    void refusesAPrefixLongerThanTheAddress() {
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("10.0.0.0/33"));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("::/129"));
    }

    @Test
    void refusesAMalformedPrefix() {
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("10.0.0.0/"));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("10.0.0.0/x"));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("10.0.0.0/8/8"));
    }

    @Test
    void refusesMalformedIpv6() {
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("2001:::1"));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse("fe80::1%eth0"));
    }

    @Test
    void refusesBlankInput() {
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse(" "));
        assertThrows(IllegalArgumentException.class, () -> IpFilter.parse(null));
    }
}
