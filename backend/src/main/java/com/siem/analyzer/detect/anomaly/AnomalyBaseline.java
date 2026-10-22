package com.siem.analyzer.detect.anomaly;

import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import smile.anomaly.IsolationForest;
import smile.anomaly.IsolationTree;

public final class AnomalyBaseline {

    private static final int EXTENSION_LEVEL = 0;

    private final IsolationForest forest;
    private final AnomalyOptions options;
    private final double threshold;
    private final long eventCount;
    private final int sampleCount;
    private final double[] medians;
    private final double[] minimums;
    private final double[] maximums;
    private final Instant start;
    private final Instant end;

    private AnomalyBaseline(
            IsolationForest forest,
            AnomalyOptions options,
            double threshold,
            long eventCount,
            int sampleCount,
            double[] medians,
            double[] minimums,
            double[] maximums,
            Instant start,
            Instant end) {
        this.forest = forest;
        this.options = options;
        this.threshold = threshold;
        this.eventCount = eventCount;
        this.sampleCount = sampleCount;
        this.medians = medians;
        this.minimums = minimums;
        this.maximums = maximums;
        this.start = start;
        this.end = end;
    }

    public static AnomalyBaseline train(Iterable<NormalizedEvent> events, AnomalyOptions options) {
        Objects.requireNonNull(events, "events");
        Objects.requireNonNull(options, "options");
        Random random = new Random();

        FeatureExtractor extractor = new FeatureExtractor(options.rateWindow());
        List<double[]> reservoir = new ArrayList<>();
        double[] minimums = new double[EventFeatures.NAMES.size()];
        double[] maximums = new double[EventFeatures.NAMES.size()];
        Arrays.fill(minimums, Double.POSITIVE_INFINITY);
        Arrays.fill(maximums, Double.NEGATIVE_INFINITY);
        long seen = 0;
        Instant start = null;
        Instant end = null;
        for (NormalizedEvent event : events) {
            EventFeatures features = extractor.extract(event);
            if (features == null) {
                continue;
            }
            Instant at = event.timestamp();
            start = start == null || at.isBefore(start) ? at : start;
            end = end == null || at.isAfter(end) ? at : end;
            double[] values = features.values();
            for (int f = 0; f < values.length; f++) {
                minimums[f] = Math.min(minimums[f], values[f]);
                maximums[f] = Math.max(maximums[f], values[f]);
            }
            seen++;
            if (reservoir.size() < options.maxBaselineEvents()) {
                reservoir.add(values);
            } else {
                long slot = random.nextLong(seen);
                if (slot < options.maxBaselineEvents()) {
                    reservoir.set((int) slot, values);
                }
            }
        }
        if (seen < options.minBaselineEvents()) {
            throw new IllegalArgumentException(
                    "a baseline needs at least "
                            + options.minBaselineEvents()
                            + " events with a status code and a source address, got "
                            + seen);
        }

        double[][] inputs = reservoir.toArray(double[][]::new);
        IsolationForest forest = grow(inputs, options, random);
        double[] scores = Arrays.stream(inputs).mapToDouble(forest::score).sorted().toArray();
        int above = (int) Math.floor(options.contamination() * scores.length);
        double threshold = scores[scores.length - 1 - above];

        return new AnomalyBaseline(
                forest,
                options,
                threshold,
                seen,
                reservoir.size(),
                medians(reservoir),
                minimums,
                maximums,
                start,
                end);
    }

    private static IsolationForest grow(double[][] inputs, AnomalyOptions options, Random random) {
        int sampleSize = Math.min(options.sampleSize(), inputs.length);
        int maxDepth = (int) Math.ceil(Math.log(sampleSize) / Math.log(2));
        int[] order = new int[inputs.length];
        Arrays.setAll(order, i -> i);

        IsolationTree[] trees = new IsolationTree[options.trees()];
        for (int t = 0; t < trees.length; t++) {

            List<double[]> sample = new ArrayList<>(sampleSize);
            for (int i = 0; i < sampleSize; i++) {
                int j = i + random.nextInt(order.length - i);
                int swap = order[i];
                order[i] = order[j];
                order[j] = swap;
                sample.add(inputs[order[i]]);
            }
            trees[t] = new IsolationTree(sample, maxDepth, EXTENSION_LEVEL);
        }

        return new IsolationForest(sampleSize, EXTENSION_LEVEL, trees);
    }

    private static double[] medians(List<double[]> rows) {
        int features = EventFeatures.NAMES.size();
        double[] medians = new double[features];
        double[] column = new double[rows.size()];
        for (int f = 0; f < features; f++) {
            for (int r = 0; r < column.length; r++) {
                column[r] = rows.get(r)[f];
            }
            Arrays.sort(column);
            medians[f] = column[(column.length - 1) / 2];
        }
        return medians;
    }

    public double score(EventFeatures features) {
        return forest.score(features.values());
    }

    public List<String> outsideRange(EventFeatures features) {
        double[] values = features.values();
        List<String> outside = new ArrayList<>(0);
        for (int f = 0; f < values.length; f++) {
            if (values[f] < minimums[f] || values[f] > maximums[f]) {
                outside.add(EventFeatures.NAMES.get(f));
            }
        }
        return outside.isEmpty() ? List.of() : Collections.unmodifiableList(outside);
    }

    public AnomalyScorer scorer() {
        return new AnomalyScorer(this);
    }

    public AnomalyOptions options() {
        return options;
    }

    public double threshold() {
        return threshold;
    }

    public long eventCount() {
        return eventCount;
    }

    public int sampleCount() {
        return sampleCount;
    }

    public double[] medians() {
        return medians.clone();
    }

    public double[] minimums() {
        return minimums.clone();
    }

    public double[] maximums() {
        return maximums.clone();
    }

    public Instant start() {
        return start;
    }

    public Instant end() {
        return end;
    }
}
