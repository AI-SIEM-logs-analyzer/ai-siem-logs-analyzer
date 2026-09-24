package com.siem.analyzer.enrich;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Parses literal IPv4 and IPv6 addresses by hand, into raw bytes, and never calls {@link
 * InetAddress#getByName}. That method falls back to the system's DNS resolver for anything it
 * cannot parse as a literal - including address-shaped strings that are not, such as {@code
 * "zzz:1"} or {@code "google.com:80"} - so a value pulled out of a log line must never reach it.
 * {@link InetAddress#getByAddress(byte[])} builds an address straight from bytes, with no lookup of
 * any kind, which is what {@link #parse} hands its result to. {@code InetAddress.ofLiteral} would
 * do the parsing itself in one call but arrived after Java 21.
 */
final class IpLiterals {

    private static final Pattern HEX_GROUP = Pattern.compile("[0-9A-Fa-f]{1,4}");

    private IpLiterals() {}

    static Optional<InetAddress> parse(String value) {
        if (value == null || value.isBlank()) {
            return Optional.empty();
        }
        String candidate = value.trim();
        Optional<byte[]> bytes = parseIpv4(candidate);
        if (bytes.isEmpty()) {
            bytes = parseIpv6(candidate);
        }
        if (bytes.isEmpty()) {
            return Optional.empty();
        }
        try {
            // bytes is always exactly 4 or 16 long here, so this never actually throws.
            // getByAddress performs no forward or reverse lookup either way.
            return Optional.of(InetAddress.getByAddress(bytes.get()));
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
    }

    /**
     * Four dot-separated decimal octets, 0-255, no leading zero. A leading zero is rejected
     * outright rather than read as decimal: some parsers read it as octal, so one spelling must not
     * silently mean two different addresses - the same concern {@link
     * com.siem.analyzer.search.IpFilter}'s own IPv4 pattern documents.
     */
    private static Optional<byte[]> parseIpv4(String candidate) {
        String[] parts = candidate.split("\\.", -1);
        if (parts.length != 4) {
            return Optional.empty();
        }
        byte[] result = new byte[4];
        for (int i = 0; i < 4; i++) {
            String part = parts[i];
            if (part.isEmpty() || part.length() > 3) {
                return Optional.empty();
            }
            for (int c = 0; c < part.length(); c++) {
                if (!Character.isDigit(part.charAt(c))) {
                    return Optional.empty();
                }
            }
            if (part.length() > 1 && part.charAt(0) == '0') {
                return Optional.empty();
            }
            int octet = Integer.parseInt(part);
            if (octet > 255) {
                return Optional.empty();
            }
            result[i] = (byte) octet;
        }
        return Optional.of(result);
    }

    /**
     * Hex groups of 1-4 digits separated by {@code :}, at most one {@code ::} run standing in for
     * one or more all-zero groups, and an optional trailing embedded IPv4 tail such as {@code
     * ::ffff:192.0.2.1}. A zone index (the {@code %eth0} suffix on a link-local address) is
     * rejected rather than stripped: it names an interface on the machine doing the parsing, not
     * something a log line or a configured range can mean anything by.
     */
    private static Optional<byte[]> parseIpv6(String candidate) {
        if (candidate.indexOf('%') >= 0) {
            return Optional.empty();
        }
        String[] halves = candidate.split(Pattern.quote("::"), -1);
        if (halves.length > 2) {
            return Optional.empty();
        }
        boolean compressed = halves.length == 2;
        List<String> head = splitGroups(halves[0]);
        List<String> tail = compressed ? splitGroups(halves[1]) : List.of();
        if (head == null || tail == null) {
            return Optional.empty();
        }

        String embeddedIpv4 = null;
        if (compressed) {
            if (!tail.isEmpty() && tail.get(tail.size() - 1).indexOf('.') >= 0) {
                embeddedIpv4 = tail.get(tail.size() - 1);
                tail = tail.subList(0, tail.size() - 1);
            }
        } else if (!head.isEmpty() && head.get(head.size() - 1).indexOf('.') >= 0) {
            embeddedIpv4 = head.get(head.size() - 1);
            head = head.subList(0, head.size() - 1);
        }

        byte[] embeddedBytes = null;
        if (embeddedIpv4 != null) {
            Optional<byte[]> parsedTail = parseIpv4(embeddedIpv4);
            if (parsedTail.isEmpty()) {
                return Optional.empty();
            }
            embeddedBytes = parsedTail.get();
        }

        for (String group : head) {
            if (!HEX_GROUP.matcher(group).matches()) {
                return Optional.empty();
            }
        }
        for (String group : tail) {
            if (!HEX_GROUP.matcher(group).matches()) {
                return Optional.empty();
            }
        }

        int embeddedSlots = embeddedBytes == null ? 0 : 2;
        int explicitSlots = head.size() + tail.size() + embeddedSlots;
        // Uncompressed addresses must spell out all 8 groups. A compressed one must leave at least
        // one group for "::" to stand in for - otherwise it is not compressing anything.
        if (compressed ? explicitSlots >= 8 : explicitSlots != 8) {
            return Optional.empty();
        }

        byte[] result = new byte[16];
        int pos = 0;
        for (String group : head) {
            writeHextet(result, pos, group);
            pos += 2;
        }
        pos += (8 - explicitSlots) * 2;
        for (String group : tail) {
            writeHextet(result, pos, group);
            pos += 2;
        }
        if (embeddedBytes != null) {
            System.arraycopy(embeddedBytes, 0, result, pos, 4);
        }
        return Optional.of(result);
    }

    /**
     * Splits one side of a {@code ::} split (or the whole address, when there is no {@code ::}) on
     * {@code :}. A stray empty group - a colon pair that is not the address's one allowed {@code
     * ::} - means the address is malformed, reported here as a {@code null} return.
     */
    private static List<String> splitGroups(String part) {
        if (part.isEmpty()) {
            return List.of();
        }
        String[] tokens = part.split(":", -1);
        for (String token : tokens) {
            if (token.isEmpty()) {
                return null;
            }
        }
        return List.of(tokens);
    }

    private static void writeHextet(byte[] out, int offset, String hex) {
        int value = Integer.parseInt(hex, 16);
        out[offset] = (byte) ((value >> 8) & 0xFF);
        out[offset + 1] = (byte) (value & 0xFF);
    }
}
