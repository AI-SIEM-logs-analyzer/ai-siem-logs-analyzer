package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.List;
import java.util.Objects;

public record EventFeatures(
        NormalizedEvent event, int requestRate, long responseBytes, int status) {

    public static final List<String> NAMES = List.of("requestRate", "responseBytes", "status");

    public EventFeatures {
        Objects.requireNonNull(event, "event");
    }

    public double[] values() {
        return new double[] {requestRate, responseBytes, status};
    }
}
