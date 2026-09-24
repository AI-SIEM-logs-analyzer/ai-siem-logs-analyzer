package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import org.junit.jupiter.api.Test;

class SkippedNetworksTest {

    private static final List<String> DEFAULTS =
            List.of(
                    "10.0.0.0/8",
                    "172.16.0.0/12",
                    "192.168.0.0/16",
                    "127.0.0.0/8",
                    "169.254.0.0/16",
                    "::1/128",
                    "fc00::/7");

    private final SkippedNetworks networks = new SkippedNetworks(DEFAULTS);

    @Test
    void skipsRfc1918Addresses() throws Exception {
        assertTrue(networks.skips(InetAddress.getByName("10.1.2.3")));
        assertTrue(networks.skips(InetAddress.getByName("172.16.0.1")));
        assertTrue(networks.skips(InetAddress.getByName("192.168.1.1")));
    }

    @Test
    void skipsLoopbackAndLinkLocal() throws Exception {
        assertTrue(networks.skips(InetAddress.getByName("127.0.0.1")));
        assertTrue(networks.skips(InetAddress.getByName("169.254.10.10")));
    }

    @Test
    void skipsIpv6LoopbackAndUniqueLocal() throws Exception {
        assertTrue(networks.skips(InetAddress.getByName("::1")));
        assertTrue(networks.skips(InetAddress.getByName("fd00::1")));
    }

    @Test
    void keepsPublicAddresses() throws Exception {
        assertFalse(networks.skips(InetAddress.getByName("8.8.8.8")));
        assertFalse(networks.skips(InetAddress.getByName("2001:4860:4860::8888")));
    }

    @Test
    void addressJustOutsideARangeIsKept() throws Exception {
        assertFalse(networks.skips(InetAddress.getByName("172.32.0.1")));
    }

    @Test
    void anUnparsableEntryIsIgnoredRatherThanFailingStartup() throws Exception {
        SkippedNetworks withJunk = new SkippedNetworks(List.of("not-a-cidr", "10.0.0.0/8"));

        assertTrue(withJunk.skips(InetAddress.getByName("10.0.0.1")));
        assertFalse(withJunk.skips(InetAddress.getByName("8.8.8.8")));
    }

    @Test
    void aHostNameIsNotTreatedAsAnAddress() {
        assertTrue(IpLiterals.parse("example.com").isEmpty());
        assertTrue(IpLiterals.parse("  ").isEmpty());
        assertTrue(IpLiterals.parse(null).isEmpty());
        assertTrue(IpLiterals.parse("999.1.1.1").isEmpty());
        assertTrue(IpLiterals.parse("8.8.8.8").isPresent());
        assertTrue(IpLiterals.parse("2001:db8::1").isPresent());
    }
}
