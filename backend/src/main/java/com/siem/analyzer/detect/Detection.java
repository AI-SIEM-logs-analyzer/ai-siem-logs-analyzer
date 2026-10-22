package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.math.BigDecimal;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

public record Detection(
        DetectionRule rule,
        Map<String, Object> group,
        BigDecimal value,
        int eventCount,
        Instant windowStart,
        Instant windowEnd,
        NormalizedEvent trigger) {

    public Detection {
        Objects.requireNonNull(rule, "rule");
        group = Collections.unmodifiableMap(new LinkedHashMap<>(group));
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(windowStart, "windowStart");
        Objects.requireNonNull(windowEnd, "windowEnd");
        Objects.requireNonNull(trigger, "trigger");
    }

    static Detection single(DetectionRule rule, NormalizedEvent event) {
        return new Detection(
                rule, Map.of(), BigDecimal.ONE, 1, event.timestamp(), event.timestamp(), event);
    }

    public String summary() {
        WindowSpec window = rule.expression().window();
        if (window == null) {
            return "matched " + rule.name();
        }
        StringBuilder summary =
                new StringBuilder()
                        .append(window.aggregation().describe())
                        .append(" = ")
                        .append(value.toPlainString())
                        .append(" (")
                        .append(window.thresholdOperator().symbol())
                        .append(' ')
                        .append(window.threshold().toPlainString())
                        .append(") within ")
                        .append(format(window.window()));
        if (!group.isEmpty()) {
            summary.append(" for ")
                    .append(
                            group.entrySet().stream()
                                    .map(entry -> entry.getKey() + "=" + entry.getValue())
                                    .collect(Collectors.joining(", ")));
        }
        return summary.toString();
    }

    private static String format(Duration duration) {
        long seconds = duration.toSeconds();
        if (seconds % 86_400 == 0) {
            return seconds / 86_400 + "d";
        }
        if (seconds % 3_600 == 0) {
            return seconds / 3_600 + "h";
        }
        if (seconds % 60 == 0) {
            return seconds / 60 + "m";
        }
        return seconds + "s";
    }
}
