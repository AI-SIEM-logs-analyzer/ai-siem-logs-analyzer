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

/**
 * What normal traffic looks like: an Isolation Forest fitted to a baseline of events, and the score
 * above which an event counts as anomalous.
 *
 * <p><b>Scores.</b> An isolation tree splits its sample on a random feature at a random value until
 * every event stands alone. Unusual events are isolated in few splits, so a short average path
 * across the forest means an outlier. Smile maps the path to a score in (0, 1): around 0.5 and
 * below is ordinary, approaching 1 is increasingly anomalous.
 *
 * <p><b>Threshold.</b> Rather than a fixed cut-off such as 0.6, the threshold is calibrated on the
 * baseline itself: every baseline event is scored, and the threshold is placed so that at most
 * {@link AnomalyOptions#contamination()} of them score above it. The forest's raw scores depend on
 * the shape of the data, while "the top 1% of what we consider normal" means the same thing on any
 * feed.
 *
 * <p><b>Range.</b> A forest cannot tell how far beyond its baseline a value lies: the trees only
 * ever split between the smallest and largest value they were grown from, so a 4 GB response scores
 * exactly like the largest response in the baseline, which may sit just under the threshold. The
 * baseline therefore also records each feature's range over every event it saw, and a value outside
 * it is anomalous whatever its score (see {@link #outsideRange}). That costs the calibration
 * nothing: no baseline event lies outside the baseline's own range.
 *
 * <p><b>Training.</b> The forest is grown here from Smile's {@link IsolationTree}s rather than with
 * {@code IsolationForest.fit}, which in Smile 4 grows every tree from the whole data set whatever
 * its {@code subsample} option says, and defaults to the extended variant, whose oblique splits mix
 * features of different scales. Each tree here gets its own random sample of {@link
 * AnomalyOptions#sampleSize()} events, is depth-limited to {@code ceil(log2(sampleSize))} as in the
 * original paper, and splits on one feature at a time.
 *
 * <p>Training is randomised, so two baselines trained on the same events score slightly
 * differently. Instances are immutable and may be shared between threads.
 */
public final class AnomalyBaseline {

    /** Axis-parallel splits: the original Isolation Forest, not the extended one. */
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

    /**
     * Trains a baseline on events taken to be normal.
     *
     * <p>Feed the events in time order, so their request rates are counted as a live feed would
     * count them. Events without a status code or source address are skipped (see {@link
     * FeatureExtractor}); a baseline of more than {@link AnomalyOptions#maxBaselineEvents()} usable
     * events is reservoir-sampled down to that.
     *
     * @throws IllegalArgumentException fewer than {@link AnomalyOptions#minBaselineEvents()} events
     *     could be scored
     */
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
            // A partial Fisher-Yates shuffle: the first sampleSize slots end up a uniform sample
            // without replacement, at a cost of sampleSize swaps rather than a full shuffle.
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
        // The path length is normalised by the expected depth of a tree grown from sampleSize
        // events, which is what each of these trees was grown from.
        return new IsolationForest(sampleSize, EXTENSION_LEVEL, trees);
    }

    /** The lower median of each feature, so it is always a value the baseline actually held. */
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

    /** Scores one event's features: higher is more anomalous. */
    public double score(EventFeatures features) {
        return forest.score(features.values());
    }

    /**
     * The features whose value lies outside anything the baseline held, in {@link
     * EventFeatures#NAMES} order; empty for an event within the baseline's range on every feature.
     */
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

    /** Starts scoring a live stream against this baseline, with an empty rate window. */
    public AnomalyScorer scorer() {
        return new AnomalyScorer(this);
    }

    public AnomalyOptions options() {
        return options;
    }

    /** Scores above this are anomalous. */
    public double threshold() {
        return threshold;
    }

    /** Usable events the baseline was trained on, before any sampling. */
    public long eventCount() {
        return eventCount;
    }

    /** Events the forest and threshold were fitted to: {@link #eventCount()}, capped. */
    public int sampleCount() {
        return sampleCount;
    }

    /** The baseline's typical value of each feature, in {@link EventFeatures#NAMES} order. */
    public double[] medians() {
        return medians.clone();
    }

    /**
     * The smallest value of each feature across the baseline, in {@link EventFeatures#NAMES} order.
     */
    public double[] minimums() {
        return minimums.clone();
    }

    /**
     * The largest value of each feature across the baseline, in {@link EventFeatures#NAMES} order.
     */
    public double[] maximums() {
        return maximums.clone();
    }

    /** The timestamp of the oldest usable baseline event. */
    public Instant start() {
        return start;
    }

    /** The timestamp of the newest usable baseline event. */
    public Instant end() {
        return end;
    }
}
