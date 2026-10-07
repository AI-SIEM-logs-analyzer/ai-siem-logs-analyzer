package com.siem.analyzer.detect.anomaly;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * Training on synthetic web traffic and scoring what departs from it.
 *
 * <p>The forest is randomised, so the assertions leave wide margins around what a run gives: the
 * attacks below sit far outside anything the baseline holds, and the bounds on false positives are
 * several times the configured contamination.
 */
class AnomalyBaselineTest {

    private static final Instant T0 = Instant.parse("2026-09-14T08:00:00Z");

    private static List<NormalizedEvent> baselineEvents;
    private static AnomalyBaseline baseline;

    @BeforeAll
    static void train() {
        baselineEvents = traffic(new Random(1), T0, Duration.ofHours(2));
        baseline = AnomalyBaseline.train(baselineEvents, AnomalyOptions.defaults());
    }

    /**
     * Ordinary traffic: two requests a second, spread over 200 clients, mostly 200s with a few
     * redirects, 304s and 404s, and response sizes log-normally distributed around 5 KB.
     */
    private static List<NormalizedEvent> traffic(Random random, Instant start, Duration span) {
        List<NormalizedEvent> events = new ArrayList<>();
        for (long ms = 0; ms < span.toMillis(); ms += 500) {
            String ip = "10.0." + random.nextInt(2) + "." + random.nextInt(100);
            double roll = random.nextDouble();
            int status;
            long bytes;
            if (roll < 0.85) {
                status = 200;
                bytes = Math.round(Math.exp(8.5 + random.nextGaussian()));
            } else if (roll < 0.93) {
                status = 304;
                bytes = 0;
            } else if (roll < 0.98) {
                status = 404;
                bytes = 200 + random.nextInt(200);
            } else {
                status = 302;
                bytes = 0;
            }
            events.add(request(ip, start.plusMillis(ms), status, bytes));
        }
        return events;
    }

    private static NormalizedEvent request(String ip, Instant at, int status, long bytes) {
        return NormalizedEvent.builder(at, LogFormat.ACCESS_LOG, "line")
                .srcIp(ip)
                .method("GET")
                .path("/")
                .status(status)
                .bytes(bytes)
                .build();
    }

    private static List<NormalizedEvent> merge(List<NormalizedEvent> a, List<NormalizedEvent> b) {
        List<NormalizedEvent> merged = new ArrayList<>(a);
        merged.addAll(b);
        merged.sort(Comparator.comparing(NormalizedEvent::timestamp));
        return merged;
    }

    private static double anomalousShare(List<NormalizedEvent> events) {
        AnomalyScorer scorer = baseline.scorer();
        return (double) scorer.detect(events).size() / events.size();
    }

    @Test
    void recordsWhatItWasTrainedOn() {
        assertEquals(baselineEvents.size(), baseline.eventCount());
        assertEquals(baselineEvents.size(), baseline.sampleCount());
        assertEquals(T0, baseline.start());
        assertEquals(baselineEvents.getLast().timestamp(), baseline.end());
        double[] medians = baseline.medians();
        assertEquals(200, medians[2]);
        assertTrue(medians[1] > 1_000 && medians[1] < 10_000, "median size " + medians[1]);
        assertArrayEquals(new double[] {1, 0, 200}, baseline.minimums());
        assertEquals(404, baseline.maximums()[2]);
    }

    @Test
    void theThresholdLeavesAtMostTheContaminationOfTheBaselineAboveIt() {
        // A fresh scorer reads the same rates training did, so these are the very scores the
        // threshold was placed among.
        double share = anomalousShare(baselineEvents);

        assertTrue(share <= 0.01, "share above threshold " + share);
        assertTrue(baseline.threshold() > 0 && baseline.threshold() < 1);
    }

    @Test
    void newOrdinaryTrafficIsRarelyFlagged() {
        List<NormalizedEvent> later =
                traffic(new Random(2), T0.plus(Duration.ofHours(2)), Duration.ofHours(1));

        double share = anomalousShare(later);

        assertTrue(share < 0.05, "false positive share " + share);
    }

    @Test
    void aScannerFloodingRequestsIsFlagged() {
        Instant start = T0.plus(Duration.ofHours(3));
        List<NormalizedEvent> scan = new ArrayList<>();
        for (int i = 0; i < 300; i++) {
            scan.add(request("198.51.100.7", start.plusMillis(i * 200L), 404, 150));
        }
        List<NormalizedEvent> events =
                merge(traffic(new Random(3), start, Duration.ofMinutes(2)), scan);

        List<AnomalyScore> anomalies = baseline.scorer().detect(events);

        long flagged =
                anomalies.stream()
                        .filter(a -> "198.51.100.7".equals(a.features().event().srcIp()))
                        .count();
        assertTrue(flagged >= 250, "scan requests flagged: " + flagged);
        long otherwise = anomalies.size() - flagged;
        assertTrue(otherwise < 15, "ordinary requests flagged alongside: " + otherwise);
    }

    @Test
    void aHugeResponseIsFlagged() {
        AnomalyScorer scorer = baseline.scorer();
        NormalizedEvent exfiltration =
                request("10.0.0.42", T0.plus(Duration.ofHours(3)), 200, 4_000_000_000L);

        AnomalyScore score = scorer.score(exfiltration).orElseThrow();

        // The forest alone scores it like the largest baseline response, which may land on either
        // side of the threshold; lying outside the baseline's range is what flags it every time.
        assertTrue(score.anomalous(), score.summary());
        assertEquals(List.of("responseBytes"), score.outsideRange());
        assertTrue(score.summary().contains("responseBytes=4000000000"), score.summary());
    }

    @Test
    void aRateAboveAnyInTheBaselineIsFlagged() {
        AnomalyScorer scorer = baseline.scorer();
        Instant at = T0.plus(Duration.ofHours(3));
        int busiest = (int) baseline.maximums()[0];
        AnomalyScore last = null;
        for (int i = 0; i <= busiest; i++) {
            last = scorer.score(request("10.0.0.42", at.plusMillis(i), 200, 5_000)).orElseThrow();
        }

        assertEquals(busiest + 1, last.features().requestRate());
        assertTrue(last.anomalous(), last.summary());
        assertEquals(List.of("requestRate"), last.outsideRange());
    }

    @Test
    void anOrdinaryRequestIsNotFlagged() {
        AnomalyScorer scorer = baseline.scorer();
        NormalizedEvent ordinary = request("10.0.0.42", T0.plus(Duration.ofHours(3)), 200, 5_000);

        AnomalyScore score = scorer.score(ordinary).orElseThrow();

        assertFalse(score.anomalous(), score.summary());
        assertEquals(List.of(), score.outsideRange());
    }

    @Test
    void theSummaryNamesTheAddressAndSetsEachFeatureBesideTheBaseline() {
        AnomalyScorer scorer = baseline.scorer();
        NormalizedEvent event = request("10.0.0.42", T0.plus(Duration.ofHours(3)), 404, 0);

        String summary = scorer.score(event).orElseThrow().summary();

        assertTrue(
                summary.matches(
                        "score 0\\.\\d{3} \\((>|<=) 0\\.\\d{3}\\) for srcIp=10\\.0\\.0\\.42:"
                                + " requestRate=1 per 1m \\(baseline median 1, range 1-\\d+\\),"
                                + " responseBytes=0 \\(baseline median \\d+, range 0-\\d+\\),"
                                + " status=404 \\(baseline median 200, range 200-404\\)"),
                summary);
    }

    @Test
    void eventsThatCannotBeScoredAreSkipped() {
        NormalizedEvent syslog =
                NormalizedEvent.builder(T0, LogFormat.SYSLOG, "line").message("cron ran").build();

        assertTrue(baseline.scorer().score(syslog).isEmpty());
    }

    @Test
    void aLongBaselineIsSampledDownButItsRatesAreCountedInFull() {
        AnomalyOptions options = AnomalyOptions.defaults().withBaselineEvents(256, 1_000);

        AnomalyBaseline sampled = AnomalyBaseline.train(baselineEvents, options);

        assertEquals(baselineEvents.size(), sampled.eventCount());
        assertEquals(1_000, sampled.sampleCount());
    }

    @Test
    void aBaselineTooSmallToCalibrateIsRefused() {
        List<NormalizedEvent> few = baselineEvents.subList(0, 100);

        IllegalArgumentException refused =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> AnomalyBaseline.train(few, AnomalyOptions.defaults()));
        assertTrue(refused.getMessage().endsWith("got 100"), refused.getMessage());
    }

    @Test
    void theForestIsFedTheFeaturesAsRecorded() {
        EventFeatures features =
                new EventFeatures(request("10.0.0.1", T0, 200, 1_000), 3, 1_000, 200);

        assertArrayEquals(new double[] {3, 1_000, 200}, features.values());
    }

    @Test
    void optionsAreValidated() {
        AnomalyOptions defaults = AnomalyOptions.defaults();

        assertThrows(IllegalArgumentException.class, () -> defaults.withContamination(0));
        assertThrows(IllegalArgumentException.class, () -> defaults.withContamination(0.5));
        assertThrows(IllegalArgumentException.class, () -> defaults.withRateWindow(Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> defaults.withBaselineEvents(1, 10));
        assertThrows(IllegalArgumentException.class, () -> defaults.withBaselineEvents(10, 5));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AnomalyOptions(0, 256, 0.01, Duration.ofMinutes(1), 256, 1_000));
        assertThrows(
                IllegalArgumentException.class,
                () -> new AnomalyOptions(100, 1, 0.01, Duration.ofMinutes(1), 256, 1_000));
    }
}
