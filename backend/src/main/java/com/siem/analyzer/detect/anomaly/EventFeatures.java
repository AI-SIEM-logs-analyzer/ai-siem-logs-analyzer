package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.List;
import java.util.Objects;

/**
 * The numbers an HTTP event is scored on.
 *
 * <p>The forest sees them as they are, with no scaling: isolation trees split each feature
 * uniformly between its own minimum and maximum, so features on different scales need no
 * normalising against each other. The response size in particular stays linear. An Isolation Forest
 * scores a value beyond anything in its baseline exactly like the baseline's most extreme value,
 * and on a linear scale that extreme is sparse and isolates fast, so a response far larger than any
 * seen before scores as anomalous. On a log scale the largest sizes are as dense as the typical
 * ones, and a 4 GB response scored no higher than an ordinary page.
 *
 * @param event the event they were read from
 * @param requestRate requests from the event's source address within the rate window, this one
 *     included
 * @param responseBytes the response size; 0 when the log has none, as Apache writes {@code -} for
 *     an empty body
 * @param status the HTTP status code
 */
public record EventFeatures(
        NormalizedEvent event, int requestRate, long responseBytes, int status) {

    /** The feature names, in the order of {@link #values()}. */
    public static final List<String> NAMES = List.of("requestRate", "responseBytes", "status");

    public EventFeatures {
        Objects.requireNonNull(event, "event");
    }

    /** The features in {@link #NAMES} order, as the forest is fed them. */
    public double[] values() {
        return new double[] {requestRate, responseBytes, status};
    }
}
