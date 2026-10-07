package com.siem.analyzer.detect.anomaly;

import java.time.Duration;
import java.util.Objects;

/**
 * How a baseline is trained.
 *
 * @param trees isolation trees in the forest; scores settle well before 100
 * @param sampleSize events each tree is grown from, ψ in the Isolation Forest paper. Small samples
 *     isolate better, not worse: 256 is the paper's default and rarely needs changing. A baseline
 *     smaller than this grows every tree from all of it
 * @param contamination the share of the baseline expected to be anomalous, which places the
 *     threshold: at most this fraction of baseline events score above it. Between 0 and 0.5
 * @param rateWindow how far back the request rate of a source address looks
 * @param minBaselineEvents fewer usable events than this and training is refused, because a
 *     threshold calibrated on a handful of events flags noise
 * @param maxBaselineEvents usable events beyond this are reservoir-sampled down to it, which bounds
 *     the memory a long baseline takes; the request rate is still counted over every event
 */
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

    /**
     * 100 trees of 256 events, 1% contamination, a one-minute rate window, and a baseline of 256 to
     * 100,000 events.
     */
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
