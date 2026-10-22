package com.siem.analyzer.detect;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

final class GroupWindow {

    private record Entry(Instant at, Object contribution) {}

    private final WindowSpec spec;
    private final PriorityQueue<Entry> entries =
            new PriorityQueue<>(Comparator.comparing(Entry::at));
    private final Map<Object, Integer> distinct = new HashMap<>();
    private BigDecimal sum = BigDecimal.ZERO;

    private Instant latest;

    private Instant floor;

    GroupWindow(WindowSpec spec) {
        this.spec = spec;
    }

    boolean add(Instant at, Object contribution) {
        if (floor != null && at.isBefore(floor)) {
            return false;
        }
        if (latest == null || at.isAfter(latest)) {
            latest = at;
        }
        Instant horizon = latest.minus(spec.window());
        if (!at.isAfter(horizon)) {
            return false;
        }
        entries.add(new Entry(at, contribution));
        include(contribution);
        while (!entries.peek().at().isAfter(horizon)) {
            exclude(entries.poll().contribution());
        }
        return true;
    }

    BigDecimal value() {
        return switch (spec.aggregation()) {
            case Aggregation.Count count -> BigDecimal.valueOf(entries.size());
            case Aggregation.DistinctCount distinctCount -> BigDecimal.valueOf(distinct.size());
            case Aggregation.Sum total -> sum;
        };
    }

    int size() {
        return entries.size();
    }

    Instant start() {
        return entries.peek().at();
    }

    Instant latest() {
        return latest;
    }

    void reset() {
        entries.clear();
        distinct.clear();
        sum = BigDecimal.ZERO;
        floor = latest;
    }

    private void include(Object contribution) {
        switch (spec.aggregation()) {
            case Aggregation.DistinctCount distinctCount ->
                    distinct.merge(contribution, 1, Integer::sum);
            case Aggregation.Sum total -> sum = sum.add((BigDecimal) contribution);
            case Aggregation.Count count -> {}
        }
    }

    private void exclude(Object contribution) {
        switch (spec.aggregation()) {
            case Aggregation.DistinctCount distinctCount ->
                    distinct.computeIfPresent(contribution, (key, n) -> n == 1 ? null : n - 1);
            case Aggregation.Sum total -> sum = sum.subtract((BigDecimal) contribution);
            case Aggregation.Count count -> {}
        }
    }
}
