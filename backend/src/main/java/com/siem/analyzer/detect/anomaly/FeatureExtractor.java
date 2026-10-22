package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.PriorityQueue;

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

    public int trackedSources() {
        return sources.size();
    }

    private void sweep() {
        sinceSweep = 0;
        Instant horizon = watermark.minus(rateWindow);
        sources.values().removeIf(source -> !source.latest.isAfter(horizon));
    }

    private final class SourceWindow {

        private final PriorityQueue<Instant> seen = new PriorityQueue<>();
        private Instant latest;

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
