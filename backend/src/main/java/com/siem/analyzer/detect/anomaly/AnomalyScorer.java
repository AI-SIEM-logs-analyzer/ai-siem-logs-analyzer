package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Scores a stream of events against one {@link AnomalyBaseline}.
 *
 * <p>The scorer keeps its own request-rate window, separate from the one the baseline was trained
 * with, so for the first {@link AnomalyOptions#rateWindow()} of a stream the rates it sees are
 * still filling up and lean low. As with the rule engine, give each stream (a live feed, a replayed
 * upload) its own scorer.
 *
 * <p>{@link #score} is synchronised, so one scorer may be shared, but events are scored one at a
 * time.
 */
public final class AnomalyScorer {

    private final AnomalyBaseline baseline;
    private final FeatureExtractor extractor;

    public AnomalyScorer(AnomalyBaseline baseline) {
        this.baseline = Objects.requireNonNull(baseline, "baseline");
        this.extractor = new FeatureExtractor(baseline.options().rateWindow());
    }

    public AnomalyBaseline baseline() {
        return baseline;
    }

    /**
     * Scores one event, whether anomalous or not.
     *
     * @return empty when the event has no status code or source address, and so cannot be scored
     */
    public synchronized Optional<AnomalyScore> score(NormalizedEvent event) {
        EventFeatures features = extractor.extract(event);
        if (features == null) {
            return Optional.empty();
        }
        return Optional.of(new AnomalyScore(features, baseline.score(features), baseline));
    }

    /** Scores events in order and returns the anomalous ones. */
    public synchronized List<AnomalyScore> detect(Iterable<NormalizedEvent> events) {
        List<AnomalyScore> anomalies = new ArrayList<>();
        for (NormalizedEvent event : events) {
            score(event).filter(AnomalyScore::anomalous).ifPresent(anomalies::add);
        }
        return anomalies;
    }
}
