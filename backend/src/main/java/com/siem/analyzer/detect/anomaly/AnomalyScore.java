package com.siem.analyzer.detect.anomaly;

import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * How one event scored against a baseline.
 *
 * @param features what the event was scored on
 * @param score the Isolation Forest score in (0, 1); higher is more anomalous
 * @param baseline the baseline it was scored against
 */
public record AnomalyScore(EventFeatures features, double score, AnomalyBaseline baseline) {

    public AnomalyScore {
        Objects.requireNonNull(features, "features");
        Objects.requireNonNull(baseline, "baseline");
    }

    public double threshold() {
        return baseline.threshold();
    }

    /** The features whose value the baseline never held; see {@link AnomalyBaseline}. */
    public List<String> outsideRange() {
        return baseline.outsideRange(features);
    }

    /**
     * Whether the event is anomalous: its score is above the baseline's threshold, or one of its
     * features lies outside the baseline's range.
     */
    public boolean anomalous() {
        return score > baseline.threshold() || !outsideRange().isEmpty();
    }

    /**
     * One line for an alert's detail, setting each feature beside the baseline, for example {@code
     * score 0.812 (> 0.640) for srcIp=203.0.113.9: requestRate=412 per 1m (baseline median 3, range
     * 1-9, outside), responseBytes=0 (baseline median 5120, range 0-91230), status=404 (baseline
     * median 200, range 200-404)}.
     */
    public String summary() {
        double[] values = features.values();
        double[] medians = baseline.medians();
        double[] minimums = baseline.minimums();
        double[] maximums = baseline.maximums();
        StringBuilder summary =
                new StringBuilder()
                        .append(String.format(Locale.ROOT, "score %.3f", score))
                        .append(score > threshold() ? " (> " : " (<= ")
                        .append(String.format(Locale.ROOT, "%.3f", threshold()))
                        .append(") for srcIp=")
                        .append(features.event().srcIp())
                        .append(": ");
        for (int f = 0; f < values.length; f++) {
            if (f > 0) {
                summary.append(", ");
            }
            summary.append(EventFeatures.NAMES.get(f)).append('=').append((long) values[f]);
            if (f == 0) {
                summary.append(" per ").append(format(baseline.options().rateWindow()));
            }
            summary.append(" (baseline median ")
                    .append((long) medians[f])
                    .append(", range ")
                    .append((long) minimums[f])
                    .append('-')
                    .append((long) maximums[f]);
            if (values[f] < minimums[f] || values[f] > maximums[f]) {
                summary.append(", outside");
            }
            summary.append(')');
        }
        return summary.toString();
    }

    private static String format(Duration duration) {
        long seconds = duration.toSeconds();
        if (seconds % 3_600 == 0) {
            return seconds / 3_600 + "h";
        }
        if (seconds % 60 == 0) {
            return seconds / 60 + "m";
        }
        return seconds + "s";
    }
}
