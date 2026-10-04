package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Runs a fixed set of {@link DetectionRule}s over a stream of events.
 *
 * <p>A rule without a window fires on every event its condition matches. A windowed rule keeps one
 * sliding window per group (see {@link GroupWindow}) and fires when the window's aggregate crosses
 * the threshold, after which that group's window starts over.
 *
 * <p><b>Time.</b> Windows run on event time, {@link NormalizedEvent#timestamp()}, never on the wall
 * clock, so replaying an uploaded file from last month detects what a live feed would have. Mild
 * disorder is absorbed: an event counts as long as it is newer than its group's window start.
 * Feeding one engine two streams whose clocks are far apart (a backfill interleaved with live
 * traffic) makes the older one look late; give each its own engine.
 *
 * <p><b>Memory.</b> State is kept only for groups that have seen a matching event within the last
 * window. Every {@value #SWEEP_INTERVAL} matching events a rule drops the groups that have gone
 * quiet for longer than a window, judged against the newest event the rule has seen.
 *
 * <p><b>Threads.</b> {@link #evaluate} is synchronised, so one engine may be shared, but events are
 * evaluated one at a time. Rules are fixed at construction; a changed rule set is a new engine.
 */
public final class RuleEngine {

    static final int SWEEP_INTERVAL = 1024;

    private final List<DetectionRule> rules;
    private final List<RuleState> states;

    /**
     * Creates an engine for a rule set, every window empty.
     *
     * @throws IllegalArgumentException two rules share a name
     */
    public RuleEngine(Collection<DetectionRule> rules) {
        Set<String> names = new HashSet<>();
        for (DetectionRule rule : rules) {
            if (!names.add(rule.name())) {
                throw new IllegalArgumentException("duplicate rule name: " + rule.name());
            }
        }
        this.rules = List.copyOf(rules);
        this.states = this.rules.stream().map(RuleState::new).toList();
    }

    public List<DetectionRule> rules() {
        return rules;
    }

    /** Feeds one event to every rule and returns what fired, in rule order. */
    public synchronized List<Detection> evaluate(NormalizedEvent event) {
        Objects.requireNonNull(event, "event");
        List<Detection> detections = new ArrayList<>(0);
        for (RuleState state : states) {
            Detection detection = state.offer(event);
            if (detection != null) {
                detections.add(detection);
            }
        }
        return detections;
    }

    /** Feeds events in order and returns everything that fired. */
    public synchronized List<Detection> evaluateAll(Iterable<NormalizedEvent> events) {
        List<Detection> detections = new ArrayList<>();
        for (NormalizedEvent event : events) {
            detections.addAll(evaluate(event));
        }
        return detections;
    }

    /** How many group windows are held across all rules; for metrics and tests. */
    public synchronized int trackedGroups() {
        return states.stream().mapToInt(state -> state.groups.size()).sum();
    }

    private static final class RuleState {

        private final DetectionRule rule;
        private final WindowSpec spec;
        private final Map<List<Object>, GroupWindow> groups = new HashMap<>();
        private Instant watermark;
        private int sinceSweep;

        RuleState(DetectionRule rule) {
            this.rule = rule;
            this.spec = rule.expression().window();
        }

        Detection offer(NormalizedEvent event) {
            if (!rule.expression().condition().test(event)) {
                return null;
            }
            if (spec == null) {
                return Detection.single(rule, event);
            }
            Object contribution = spec.aggregation().contribution(event);
            List<Object> key = spec.groupKey(event);
            if (contribution == null || key == null) {
                return null;
            }

            Instant at = event.timestamp();
            if (watermark == null || at.isAfter(watermark)) {
                watermark = at;
            }
            if (++sinceSweep >= SWEEP_INTERVAL) {
                sweep();
            }

            GroupWindow window = groups.computeIfAbsent(key, k -> new GroupWindow(spec));
            if (!window.add(at, contribution) || !spec.isMet(window.value())) {
                return null;
            }
            Detection detection =
                    new Detection(
                            rule,
                            spec.label(key),
                            window.value(),
                            window.size(),
                            window.start(),
                            window.latest(),
                            event);
            window.reset();
            return detection;
        }

        private void sweep() {
            sinceSweep = 0;
            Instant horizon = watermark.minus(spec.window());
            groups.values().removeIf(window -> !window.latest().isAfter(horizon));
        }
    }
}
