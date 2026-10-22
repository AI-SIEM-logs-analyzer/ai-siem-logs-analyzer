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

public final class RuleEngine {

    static final int SWEEP_INTERVAL = 1024;

    private final List<DetectionRule> rules;
    private final List<RuleState> states;

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

    public synchronized List<Detection> evaluateAll(Iterable<NormalizedEvent> events) {
        List<Detection> detections = new ArrayList<>();
        for (NormalizedEvent event : events) {
            detections.addAll(evaluate(event));
        }
        return detections;
    }

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
