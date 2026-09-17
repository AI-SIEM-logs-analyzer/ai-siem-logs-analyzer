package com.siem.analyzer.search;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * One source-address filter: a single address or a CIDR range, IPv4 or IPv6.
 *
 * <p>Validated here rather than left to the engine, which would answer a malformed value with a 400
 * of its own that the search path reports as the engine being down. The check is purely textual:
 * {@link InetAddress#getByName} resolves anything that is not a literal, and a search parameter
 * must never become a DNS query.
 *
 * @param value the address or range as the engine's {@code ip} field accepts it, for example {@code
 *     203.0.113.7} or {@code 10.0.0.0/8}
 */
public record IpFilter(String value) {

    // Four dotted decimal octets only. The JDK also accepts "127.1" and octal or hex parts,
    // which read as one address and match another.
    private static final Pattern IPV4 =
            Pattern.compile(
                    "((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");

    // Hex groups, colons and an optional embedded IPv4 tail. No zone id: it names an interface
    // on this host and means nothing to an indexed address.
    private static final Pattern IPV6_CHARACTERS = Pattern.compile("[0-9A-Fa-f:.]+");

    private static final Pattern PREFIX = Pattern.compile("\\d{1,3}");

    public IpFilter {
        if (value == null) {
            throw new IllegalArgumentException("srcIp is required");
        }
    }

    /** Parses one {@code srcIp} parameter value, trimming surrounding whitespace. */
    public static IpFilter parse(String raw) {
        String candidate = raw == null ? "" : raw.trim();
        if (candidate.isEmpty()) {
            throw new IllegalArgumentException("srcIp must not be blank");
        }

        String address = candidate;
        String prefix = null;
        int slash = candidate.indexOf('/');
        if (slash >= 0) {
            address = candidate.substring(0, slash);
            prefix = candidate.substring(slash + 1);
        }

        int bits;
        if (IPV4.matcher(address).matches()) {
            bits = 32;
        } else if (isIpv6(address)) {
            bits = 128;
        } else {
            throw invalid(candidate);
        }

        if (prefix != null) {
            if (!PREFIX.matcher(prefix).matches() || Integer.parseInt(prefix) > bits) {
                throw invalid(candidate);
            }
        }
        return new IpFilter(candidate);
    }

    private static boolean isIpv6(String address) {
        if (!address.contains(":") || !IPV6_CHARACTERS.matcher(address).matches()) {
            return false;
        }
        try {
            // Safe to hand to the resolver now: a string with a colon is only ever parsed as an
            // IPv6 literal, never looked up.
            return InetAddress.getByName(address) instanceof Inet6Address;
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private static IllegalArgumentException invalid(String candidate) {
        return new IllegalArgumentException(
                "srcIp must be an IP address or CIDR range, for example 10.0.0.0/8: " + candidate);
    }
}
