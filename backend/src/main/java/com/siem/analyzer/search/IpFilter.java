package com.siem.analyzer.search;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

public record IpFilter(String value) {

    private static final Pattern IPV4 =
            Pattern.compile(
                    "((25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)\\.){3}(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)");

    private static final Pattern IPV6_CHARACTERS = Pattern.compile("[0-9A-Fa-f:.]+");

    private static final Pattern PREFIX = Pattern.compile("\\d{1,3}");

    public IpFilter {
        if (value == null) {
            throw new IllegalArgumentException("srcIp is required");
        }
    }

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
