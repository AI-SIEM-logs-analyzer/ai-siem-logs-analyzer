package com.siem.analyzer.detect.anomaly;

import java.time.Duration;
import java.util.Objects;

public record AnomalyOptions(
        int trees,
        int sampleSize,
        double contamination,
        Duration rateWindow,
        int minBaselineEvents,
        int maxBaselineEvents) {

    public AnomalyOptions {
        if (trees < 1) {
            throw new IllegalArgumentException("trees must be at least 1: " + trees);
        }
        if (sampleSize < 2) {
            throw new IllegalArgumentException("sampleSize must be at least 2: " + sampleSize);
        }
        if (!(contamination > 0 && contamination < 0.5)) {
            throw new IllegalArgumentException(
                    "contamination must be between 0 and 0.5: " + contamination);
        }
        Objects.requireNonNull(rateWindow, "rateWindow");
        if (rateWindow.isNegative() || rateWindow.isZero()) {
            throw new IllegalArgumentException("rateWindow must be positive: " + rateWindow);
        }
        if (minBaselineEvents < 2) {
            throw new IllegalArgumentException(
                    "minBaselineEvents must be at least 2: " + minBaselineEvents);
        }
        if (maxBaselineEvents < minBaselineEvents) {
            throw new IllegalArgumentException(
                    "maxBaselineEvents must be at least minBaselineEvents: " + maxBaselineEvents);
        }
    }

    public static AnomalyOptions defaults() {
        return new AnomalyOptions(100, 256, 0.01, Duration.ofMinutes(1), 256, 100_000);
    }

    public AnomalyOptions withContamination(double contamination) {
        return new AnomalyOptions(
                trees, sampleSize, contamination, rateWindow, minBaselineEvents, maxBaselineEvents);
    }

    public AnomalyOptions withRateWindow(Duration rateWindow) {
        return new AnomalyOptions(
                trees, sampleSize, contamination, rateWindow, minBaselineEvents, maxBaselineEvents);
    }

    public AnomalyOptions withBaselineEvents(int min, int max) {
        return new AnomalyOptions(trees, sampleSize, contamination, rateWindow, min, max);
    }
}
