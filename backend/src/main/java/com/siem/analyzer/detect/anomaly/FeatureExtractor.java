package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;

/**
 * Turns a stream of events into {@link EventFeatures}, counting each source address's requests over
 * a sliding window.
 *
 * <p>Only events with a status code and a source address are scored: the status is one of the
 * features, and the request rate is counted per address. Everything else (syslog lines, JSON events
 * without a status) yields {@code null}.
 *
 * <p><b>Time.</b> The window runs on event time, like the rule engine's: an address's rate is how
 * many of its requests fall within {@code (latest - window, latest]}, {@code latest} being the
 * newest timestamp it has sent. Events should arrive roughly in order; one older than its address's
 * window still gets features but does not raise that address's rate.
 *
 * <p><b>Memory.</b> Every {@value #SWEEP_INTERVAL} events, addresses that have gone quiet for
 * longer than a window are dropped.
 *
 * <p>Not thread-safe.
 */
public final class FeatureExtractor {

    static final int SWEEP_INTERVAL = 1024;

    private final Duration rateWindow;
    private final Map<String, SourceWindow> sources = new HashMap<>();
    private Instant watermark;
    private int sinceSweep;

    public FeatureExtractor(Duration rateWindow) {
        Objects.requireNonNull(rateWindow, "rateWindow");
        if (rateWindow.isNegative() || rateWindow.isZero()) {
            throw new IllegalArgumentException("rateWindow must be positive: " + rateWindow);
        }
        this.rateWindow = rateWindow;
    }

    /** Reads the event's features; {@code null} when it has no status code or no source address. */
    public EventFeatures extract(NormalizedEvent event) {
        Objects.requireNonNull(event, "event");
        if (event.status() == null || event.srcIp() == null) {
            return null;
        }
        Instant at = event.timestamp();
        if (watermark == null || at.isAfter(watermark)) {
            watermark = at;
        }
        if (++sinceSweep >= SWEEP_INTERVAL) {
            sweep();
        }
        int rate = sources.computeIfAbsent(event.srcIp(), ip -> new SourceWindow()).add(at);
        long bytes = event.bytes() == null ? 0 : event.bytes();
        return new EventFeatures(event, rate, bytes, event.status());
    }

    /** How many source addresses are being tracked; for metrics and tests. */
    public int trackedSources() {
        return sources.size();
    }

    private void sweep() {
        sinceSweep = 0;
        Instant horizon = watermark.minus(rateWindow);
        sources.values().removeIf(source -> !source.latest.isAfter(horizon));
    }

    /** The recent requests of one address, oldest first. */
    private final class SourceWindow {

        private final PriorityQueue<Instant> seen = new PriorityQueue<>();
        private Instant latest;

        /** Records a request and returns how many the window now holds. */
        int add(Instant at) {
            if (latest == null || at.isAfter(latest)) {
                latest = at;
            }
            Instant horizon = latest.minus(rateWindow);
            if (at.isAfter(horizon)) {
                seen.add(at);
            }
            while (!seen.peek().isAfter(horizon)) {
                seen.poll();
            }
            return seen.size();
        }
    }
}
