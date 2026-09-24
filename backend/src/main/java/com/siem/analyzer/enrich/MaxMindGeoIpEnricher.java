package com.siem.analyzer.enrich;

import com.maxmind.db.CHMCache;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.model.AsnResponse;
import com.maxmind.geoip2.model.CityResponse;
import com.siem.analyzer.config.AppConfig;
import io.quarkus.runtime.LaunchMode;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;

/**
 * Looks addresses up in the bundled GeoLite2 databases.
 *
 * <p>The readers are built from a {@link File} rather than a classpath stream on purpose: a reader
 * built from a stream holds the whole database in the heap, which for GeoLite2-City is roughly 70
 * MB, while a reader built from a file memory-maps it.
 */
@ApplicationScoped
public class MaxMindGeoIpEnricher implements GeoIpEnricher {

    private static final Logger LOG = Logger.getLogger(MaxMindGeoIpEnricher.class);

    private final boolean enabled;
    private final String cityPath;
    private final String asnPath;
    private final SkippedNetworks skippedNetworks;
    private final boolean failFast;

    private DatabaseReader cityReader;
    private DatabaseReader asnReader;
    private volatile boolean active;

    @Inject
    public MaxMindGeoIpEnricher(AppConfig config) {
        this(
                config.geoip().enabled(),
                config.geoip().cityDatabasePath(),
                config.geoip().asnDatabasePath(),
                config.geoip().skippedNetworks(),
                LaunchMode.current() == LaunchMode.NORMAL);
    }

    // Used by tests: always non-fail-fast, so a missing database disables enrichment for the run
    // instead of throwing. LaunchMode.current() is unreliable in a plain JUnit test that runs
    // outside a Quarkus runtime, so fail-fast behaviour is taken as an explicit argument instead
    // of being derived in here; the CDI constructor above is the only caller that derives it.
    MaxMindGeoIpEnricher(boolean enabled, String cityPath, String asnPath, List<String> skipped) {
        this(enabled, cityPath, asnPath, skipped, false);
    }

    private MaxMindGeoIpEnricher(
            boolean enabled,
            String cityPath,
            String asnPath,
            List<String> skipped,
            boolean failFast) {
        this.enabled = enabled;
        this.cityPath = cityPath;
        this.asnPath = asnPath;
        this.skippedNetworks = new SkippedNetworks(skipped);
        this.failFast = failFast;
    }

    @PostConstruct
    void open() {
        if (!enabled) {
            LOG.info("GeoIP enrichment is disabled; events will carry no geo fields");
            return;
        }
        try {
            cityReader = reader(cityPath);
            asnReader = reader(asnPath);
            active = true;
            LOG.infof("GeoIP enrichment active (city=%s, asn=%s)", cityPath, asnPath);
        } catch (IOException e) {
            closeQuietly();
            if (failFast) {
                // A packaged deployment that asked for enrichment and cannot read its databases is
                // misconfigured. Fail loudly at boot rather than silently indexing events without
                // geo.
                throw new IllegalStateException("Cannot open the GeoIP databases", e);
            }
            LOG.warnf(e, "Cannot open the GeoIP databases; enrichment is off for this run");
        }
    }

    private static DatabaseReader reader(String path) throws IOException {
        return new DatabaseReader.Builder(new File(path)).withCache(new CHMCache()).build();
    }

    @PreDestroy
    void close() {
        closeQuietly();
    }

    private void closeQuietly() {
        active = false;
        cityReader = closed(cityReader);
        asnReader = closed(asnReader);
    }

    private DatabaseReader closed(DatabaseReader reader) {
        if (reader != null) {
            try {
                reader.close();
            } catch (IOException e) {
                LOG.debugf(e, "Failed to close a GeoIP database reader");
            }
        }
        return null;
    }

    @Override
    public Optional<GeoEnrichment> lookup(String ip) {
        if (!active) {
            return Optional.empty();
        }
        InetAddress address = IpLiterals.parse(ip).orElse(null);
        if (address == null || skippedNetworks.skips(address)) {
            return Optional.empty();
        }
        GeoEnrichment enrichment = combine(city(address), asn(address));
        return enrichment.isEmpty() ? Optional.empty() : Optional.of(enrichment);
    }

    private Optional<CityResponse> city(InetAddress address) {
        try {
            return cityReader.tryCity(address);
        } catch (Exception e) {
            // A lookup failure is never allowed to fail an ingestion batch. The event simply
            // carries no geo fields. Logged by the address's literal form only: this class must
            // never call getHostName or getCanonicalHostName on an InetAddress parsed from an
            // untrusted log line, since either can trigger a reverse-DNS lookup.
            LOG.debugf(e, "City lookup failed for %s", address.getHostAddress());
            return Optional.empty();
        }
    }

    private Optional<AsnResponse> asn(InetAddress address) {
        try {
            return asnReader.tryAsn(address);
        } catch (Exception e) {
            LOG.debugf(e, "ASN lookup failed for %s", address.getHostAddress());
            return Optional.empty();
        }
    }

    private static GeoEnrichment combine(Optional<CityResponse> city, Optional<AsnResponse> asn) {
        String countryIso = city.map(c -> c.getCountry().getIsoCode()).orElse(null);
        String countryName = city.map(c -> c.getCountry().getName()).orElse(null);
        String cityName = city.map(c -> c.getCity().getName()).orElse(null);
        Double latitude = city.map(c -> c.getLocation().getLatitude()).orElse(null);
        Double longitude = city.map(c -> c.getLocation().getLongitude()).orElse(null);
        Long asNumber = asn.map(a -> toLong(a.getAutonomousSystemNumber())).orElse(null);
        String asOrg = asn.map(AsnResponse::getAutonomousSystemOrganization).orElse(null);
        return new GeoEnrichment(
                countryIso, countryName, cityName, latitude, longitude, asNumber, asOrg);
    }

    private static Long toLong(Number value) {
        return value == null ? null : value.longValue();
    }
}
