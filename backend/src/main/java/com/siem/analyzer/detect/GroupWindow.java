package com.siem.analyzer.detect;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;

/**
 * The sliding window of one group of one rule.
 *
 * <p>The window is {@code (latest - window, latest]} in event time, {@code latest} being the newest
 * timestamp the group has seen. Events are kept in a heap ordered by timestamp, so one that arrives
 * out of order still lands in the window as long as it is not already older than its start, and
 * expiry always removes the oldest first. The aggregate is maintained as events enter and leave, so
 * reading it never rescans the window.
 *
 * <p>Not thread-safe; the {@link RuleEngine} serialises access.
 */
final class GroupWindow {

    private record Entry(Instant at, Object contribution) {}

    private final WindowSpec spec;
    private final PriorityQueue<Entry> entries =
            new PriorityQueue<>(Comparator.comparing(Entry::at));
    private final Map<Object, Integer> distinct = new HashMap<>();
    private BigDecimal sum = BigDecimal.ZERO;

    /** The newest timestamp the group has seen; survives {@link #reset()}. */
    private Instant latest;

    /** Events older than this were in a window that already fired, and are not counted again. */
    private Instant floor;

    GroupWindow(WindowSpec spec) {
        this.spec = spec;
    }

    /**
     * Adds an event's contribution and expires what the window has moved past.
     *
     * @return whether the event was counted; {@code false} when it is too old for the window
     */
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

    /** The aggregate over what the window holds now. */
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

    /** The oldest timestamp in the window; only meaningful while it is not empty. */
    Instant start() {
        return entries.peek().at();
    }

    Instant latest() {
        return latest;
    }

    /**
     * Empties the window after it fired.
     *
     * <p>Starting over is what keeps one burst from raising an alert on every event after the
     * threshold: ten failed logins fire once, and it takes ten more to fire again. The floor stops
     * a straggler from the burst that already fired from opening the next one.
     */
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
            case Aggregation.Count count -> {
                // The heap's size is the count.
            }
        }
    }

    private void exclude(Object contribution) {
        switch (spec.aggregation()) {
            case Aggregation.DistinctCount distinctCount ->
                    distinct.computeIfPresent(contribution, (key, n) -> n == 1 ? null : n - 1);
            case Aggregation.Sum total -> sum = sum.subtract((BigDecimal) contribution);
            case Aggregation.Count count -> {
                // The heap's size is the count.
            }
        }
    }
}
