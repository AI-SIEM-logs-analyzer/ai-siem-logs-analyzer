package com.siem.analyzer.detect.anomaly;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.parse.AccessLogParser;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class FeatureExtractorTest {

    private static final Instant T0 = Instant.parse("2026-09-14T10:00:00Z");

    private final FeatureExtractor extractor = new FeatureExtractor(Duration.ofMinutes(1));

    private static NormalizedEvent request(String ip, int second) {
        return NormalizedEvent.builder(T0.plusSeconds(second), LogFormat.ACCESS_LOG, "line")
                .srcIp(ip)
                .status(200)
                .bytes(512L)
                .build();
    }

    @Test
    void readsStatusAndResponseSizeFromAParsedAccessLogLine() {
        NormalizedEvent event =
                new AccessLogParser()
                        .parse(
                                "203.0.113.9 - - [14/Sep/2026:10:00:00 +0000]"
                                        + " \"GET /index.html HTTP/1.1\" 404 1234")
                        .orElseThrow();

        EventFeatures features = extractor.extract(event);

        assertEquals(1, features.requestRate());
        assertEquals(1234, features.responseBytes());
        assertEquals(404, features.status());
    }

    @Test
    void countsEachAddressSeparatelyWithinTheWindow() {
        extractor.extract(request("10.0.0.1", 0));
        extractor.extract(request("10.0.0.1", 10));
        extractor.extract(request("10.0.0.2", 20));

        assertEquals(3, extractor.extract(request("10.0.0.1", 30)).requestRate());
        assertEquals(2, extractor.extract(request("10.0.0.2", 40)).requestRate());
    }

    @Test
    void requestsOlderThanTheWindowStopCounting() {
        extractor.extract(request("10.0.0.1", 0));
        extractor.extract(request("10.0.0.1", 30));

        // The window is (t - 1m, t]: at 60s the request at 0s has just left it.
        assertEquals(2, extractor.extract(request("10.0.0.1", 60)).requestRate());
        assertEquals(1, extractor.extract(request("10.0.0.1", 200)).requestRate());
    }

    @Test
    void aLateRequestDoesNotRaiseTheRate() {
        extractor.extract(request("10.0.0.1", 120));

        assertEquals(1, extractor.extract(request("10.0.0.1", 0)).requestRate());
        assertEquals(2, extractor.extract(request("10.0.0.1", 121)).requestRate());
    }

    @Test
    void aMissingResponseSizeCountsAsEmpty() {
        NormalizedEvent event =
                NormalizedEvent.builder(T0, LogFormat.ACCESS_LOG, "line")
                        .srcIp("10.0.0.1")
                        .status(304)
                        .build();

        assertEquals(0, extractor.extract(event).responseBytes());
    }

    @Test
    void eventsWithoutStatusOrAddressAreNotScored() {
        NormalizedEvent syslog =
                NormalizedEvent.builder(T0, LogFormat.SYSLOG, "line")
                        .srcIp("10.0.0.1")
                        .message("Accepted publickey for deploy")
                        .build();
        NormalizedEvent anonymous =
                NormalizedEvent.builder(T0, LogFormat.ACCESS_LOG, "line").status(200).build();

        assertNull(extractor.extract(syslog));
        assertNull(extractor.extract(anonymous));
        assertEquals(0, extractor.trackedSources());
    }

    @Test
    void quietAddressesAreForgotten() {
        for (int i = 0; i < 100; i++) {
            extractor.extract(request("10.0.1." + i, 0));
        }
        // One busy address an hour later; the sweep runs every SWEEP_INTERVAL events.
        for (int i = 0; i < FeatureExtractor.SWEEP_INTERVAL; i++) {
            extractor.extract(request("10.0.0.1", 3_600));
        }

        assertEquals(1, extractor.trackedSources());
    }

    @Test
    void theWindowMustBePositive() {
        assertThrows(IllegalArgumentException.class, () -> new FeatureExtractor(Duration.ZERO));
    }
}
