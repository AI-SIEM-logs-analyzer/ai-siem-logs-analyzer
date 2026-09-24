package com.siem.analyzer.enrich;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * Decides which addresses are worth a database lookup. Private, loopback and link-local space is
 * skipped: the databases have nothing for it, so a lookup would only cost time.
 */
final class SkippedNetworks {

    private static final Logger LOG = Logger.getLogger(SkippedNetworks.class);

    private final List<Cidr> networks;

    SkippedNetworks(List<String> configured) {
        List<Cidr> parsed = new ArrayList<>();
        for (String entry : configured) {
            Cidr cidr = Cidr.parse(entry);
            if (cidr == null) {
                // A bad entry disables one range, not the whole enricher: enrichment is additive
                // and must
                // never be the reason the application refuses to start.
                LOG.warnf("Ignoring unparsable app.geoip.skipped-networks entry: %s", entry);
            } else {
                parsed.add(cidr);
            }
        }
        this.networks = List.copyOf(parsed);
    }

    boolean skips(InetAddress address) {
        byte[] bytes = address.getAddress();
        for (Cidr network : networks) {
            if (network.contains(bytes)) {
                return true;
            }
        }
        return false;
    }

    /** One configured range, held as its raw prefix bytes and prefix length. */
    private record Cidr(byte[] prefix, int bits) {

        static Cidr parse(String entry) {
            int slash = entry.indexOf('/');
            if (slash < 0) {
                return null;
            }
            InetAddress address = IpLiterals.parse(entry.substring(0, slash)).orElse(null);
            if (address == null) {
                return null;
            }
            int bits;
            try {
                bits = Integer.parseInt(entry.substring(slash + 1).trim());
            } catch (NumberFormatException e) {
                return null;
            }
            byte[] prefix = address.getAddress();
            if (bits < 0 || bits > prefix.length * 8) {
                return null;
            }
            return new Cidr(prefix, bits);
        }

        boolean contains(byte[] address) {
            if (address.length != prefix.length) {
                return false;
            }
            int fullBytes = bits / 8;
            for (int i = 0; i < fullBytes; i++) {
                if (address[i] != prefix[i]) {
                    return false;
                }
            }
            int remaining = bits % 8;
            if (remaining == 0) {
                return true;
            }
            int mask = 0xFF << (8 - remaining);
            return (address[fullBytes] & mask) == (prefix[fullBytes] & mask);
        }
    }
}
