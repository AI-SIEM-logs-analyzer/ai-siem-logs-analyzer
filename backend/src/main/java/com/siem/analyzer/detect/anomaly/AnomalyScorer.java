package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

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

    public synchronized Optional<AnomalyScore> score(NormalizedEvent event) {
        EventFeatures features = extractor.extract(event);
        if (features == null) {
            return Optional.empty();
        }
        return Optional.of(new AnomalyScore(features, baseline.score(features), baseline));
    }

    public synchronized List<AnomalyScore> detect(Iterable<NormalizedEvent> events) {
        List<AnomalyScore> anomalies = new ArrayList<>();
        for (NormalizedEvent event : events) {
            score(event).filter(AnomalyScore::anomalous).ifPresent(anomalies::add);
        }
        return anomalies;
    }
}
