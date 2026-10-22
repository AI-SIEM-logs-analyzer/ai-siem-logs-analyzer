package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.loadgen.SyntheticLogGenerator;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Options;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Stream;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Summary;
import com.siem.analyzer.parse.AccessLogParser;
import com.siem.analyzer.parse.JsonLogParser;
import com.siem.analyzer.parse.ParserFixtures;
import com.siem.analyzer.parse.SyslogParser;
import com.siem.analyzer.service.LogFormatDetector;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class DetectionConfusionMatrixTest {

    private static final Instant START = Instant.parse("2026-09-24T00:00:00Z");
    private static final long EVENTS = 100_000;
    private static final long SEED = 42;

    private static final String GENERATED = "";

    private static final String LOOKALIKES = "benign-lookalikes";

    private static final List<DetectionRule> RULES =
            List.of(
                    BruteForceLoginRule.rule(),
                    SqlInjectionRule.rule(),
                    PathTraversalRule.rule(),
                    ScannerUserAgentRule.rule());

    record Confusion(long tp, long fp, long tn, long fn) {

        long total() {
            return tp + fp + tn + fn;
        }

        double precision() {
            return ratio(tp, tp + fp);
        }

        double recall() {
            return ratio(tp, tp + fn);
        }

        double falsePositiveRate() {
            return ratio(fp, fp + tn);
        }

        double f1() {
            double p = precision();
            double r = recall();
            return p + r == 0 ? 0 : 2 * p * r / (p + r);
        }

        private static double ratio(long part, long whole) {
            return whole == 0 ? 0 : (double) part / whole;
        }
    }

    private record Line(String file, long number, String label, NormalizedEvent event) {}

    private Path dir;
    private Summary summary;
    private List<Line> lines;
    private Map<String, Set<Line>> flagged;
    private Map<String, Confusion> matrices;
    private Confusion anyRule;

    @BeforeAll
    void detectOnSyntheticLogs(@TempDir Path dir) throws IOException, URISyntaxException {
        this.dir = dir;
        Path scenarios =
                Path.of(
                        DetectionConfusionMatrixTest.class
                                .getResource("/detection-scenarios")
                                .toURI());
        summary =
                SyntheticLogGenerator.generate(
                        new Options(
                                EVENTS,
                                dir,
                                SEED,
                                START,
                                Duration.ofDays(1),
                                EnumSet.allOf(Stream.class),
                                Options.DEFAULT_MAX_FILE_BYTES,
                                scenarios,
                                -1));
        lines = parse(groundTruth());
        flagged = detect();

        matrices = new LinkedHashMap<>();
        for (DetectionRule rule : RULES) {
            matrices.put(
                    rule.name(),
                    confusion(
                            line -> rule.name().equals(line.label()),
                            line -> flagged.get(rule.name()).contains(line)));
        }
        Set<String> attacks = matrices.keySet();
        anyRule =
                confusion(
                        line -> attacks.contains(line.label()),
                        line -> flagged.values().stream().anyMatch(set -> set.contains(line)));
        System.out.print(report());
    }

    static List<String> ruleNames() {
        return RULES.stream().map(DetectionRule::name).toList();
    }

    @Test
    void everyWrittenLineIsScored() {
        assertEquals(summary.events(), lines.size());
        for (Confusion matrix : matrices.values()) {
            assertEquals(lines.size(), matrix.total());
        }
        assertEquals(lines.size(), anyRule.total());
    }

    @Test
    void everyScenarioWasInjected() {
        Set<String> labels = new TreeSet<>(summary.injectedPerLabel().keySet());

        assertTrue(labels.containsAll(matrices.keySet()), "a rule without scenarios: " + labels);
        assertTrue(labels.contains(LOOKALIKES), labels.toString());
    }

    @ParameterizedTest
    @MethodSource("ruleNames")
    void ruleFindsEveryInjectedAttack(String rule) {
        Confusion matrix = matrices.get(rule);

        assertTrue(matrix.tp() > 0, rule + " has no attack lines to find");
        assertEquals(0, matrix.fn(), () -> rule + " missed:\n" + misses(rule));
    }

    @ParameterizedTest
    @MethodSource("ruleNames")
    void ruleRaisesNoFalseAlarm(String rule) {
        Confusion matrix = matrices.get(rule);

        assertEquals(0, matrix.fp(), () -> rule + " fired on:\n" + falseAlarms(rule));
        assertEquals(1.0, matrix.precision());
    }

    @Test
    void benignLookalikesRaiseNothing() {
        List<String> fired =
                lines.stream()
                        .filter(line -> line.label().equals(LOOKALIKES))
                        .filter(line -> flagged.values().stream().anyMatch(s -> s.contains(line)))
                        .map(line -> line.event().raw())
                        .toList();

        assertEquals(List.of(), fired);
    }

    @Test
    void anyRuleSeparatesAttacksFromTheRest() {
        assertEquals(1.0, anyRule.recall());
        assertEquals(0.0, anyRule.falsePositiveRate());
        assertEquals(summary.injected() - summary.injectedPerLabel().get(LOOKALIKES), anyRule.tp());
    }

    private Map<String, String> groundTruth() throws IOException {
        List<String> rows = Files.readAllLines(dir.resolve("ground-truth.csv"));
        assertEquals("file,line,timestamp,label,instance,origin", rows.getFirst());
        Map<String, String> labels = new HashMap<>();
        for (String row : rows.subList(1, rows.size())) {
            String[] cells = row.split(",", 6);
            labels.put(cells[0] + ":" + cells[1], cells[3]);
        }
        return labels;
    }

    private List<Line> parse(Map<String, String> labels) throws IOException {
        AccessLogParser access = new AccessLogParser();
        SyslogParser syslog = new SyslogParser();
        JsonLogParser json =
                ParserFixtures.json(Clock.fixed(START.plus(Duration.ofDays(1)), ZoneOffset.UTC));
        LogFormatDetector detector = new LogFormatDetector(8192);

        List<Line> parsed = new ArrayList<>();
        for (String file : summary.linesPerFile().keySet()) {
            Path path = dir.resolve(file);
            LogFormat format = detector.detect(path, file);
            Function<String, Optional<NormalizedEvent>> parser =
                    switch (format) {
                        case ACCESS_LOG -> access::parse;
                        case SYSLOG -> syslog::parse;
                        case JSON -> json::parse;
                        default -> throw new AssertionError(file + " read as " + format);
                    };
            long number = 0;
            for (String raw : Files.readAllLines(path)) {
                number++;
                NormalizedEvent event =
                        parser.apply(raw).orElseThrow(() -> new AssertionError("unparsed: " + raw));
                String label = labels.getOrDefault(file + ":" + number, GENERATED);
                parsed.add(new Line(file, number, label, event));
            }
        }

        parsed.sort(Comparator.comparing(line -> line.event().timestamp()));
        return parsed;
    }

    private Map<String, Set<Line>> detect() {
        RuleEngine engine = new RuleEngine(RULES);
        Map<NormalizedEvent, Line> byEvent = new IdentityHashMap<>();
        for (Line line : lines) {
            byEvent.put(line.event(), line);
        }
        List<Detection> detections = engine.evaluateAll(lines.stream().map(Line::event).toList());

        Map<String, Set<Line>> result = new LinkedHashMap<>();
        for (DetectionRule rule : RULES) {
            result.put(rule.name(), identitySet());
        }
        Map<String, Map<Map<String, Object>, List<Line>>> matchingByGroup = new HashMap<>();
        for (Detection detection : detections) {
            DetectionRule rule = detection.rule();
            Set<Line> hits = result.get(rule.name());
            WindowSpec window = rule.expression().window();
            if (window == null) {
                hits.add(byEvent.get(detection.trigger()));
                continue;
            }
            List<Line> candidates =
                    matchingByGroup
                            .computeIfAbsent(rule.name(), name -> matchingByGroup(rule))
                            .getOrDefault(detection.group(), List.of());
            for (Line line : candidates) {
                Instant at = line.event().timestamp();
                if (!at.isBefore(detection.windowStart()) && !at.isAfter(detection.windowEnd())) {
                    hits.add(line);
                }
            }
        }
        return result;
    }

    private Map<Map<String, Object>, List<Line>> matchingByGroup(DetectionRule rule) {
        WindowSpec window = rule.expression().window();
        Map<Map<String, Object>, List<Line>> groups = new HashMap<>();
        for (Line line : lines) {
            if (!rule.expression().condition().test(line.event())) {
                continue;
            }
            List<Object> key = window.groupKey(line.event());
            if (key != null) {
                groups.computeIfAbsent(window.label(key), k -> new ArrayList<>()).add(line);
            }
        }
        return groups;
    }

    private Confusion confusion(Predicate<Line> actual, Predicate<Line> flags) {
        long tp = 0;
        long fp = 0;
        long tn = 0;
        long fn = 0;
        for (Line line : lines) {
            boolean attack = actual.test(line);
            boolean hit = flags.test(line);
            if (attack && hit) {
                tp++;
            } else if (hit) {
                fp++;
            } else if (attack) {
                fn++;
            } else {
                tn++;
            }
        }
        return new Confusion(tp, fp, tn, fn);
    }

    private static Set<Line> identitySet() {
        return Collections.newSetFromMap(new IdentityHashMap<>());
    }

    private String misses(String rule) {
        return describe(
                lines.stream()
                        .filter(line -> rule.equals(line.label()))
                        .filter(line -> !flagged.get(rule).contains(line)));
    }

    private String falseAlarms(String rule) {
        return describe(
                lines.stream()
                        .filter(line -> !rule.equals(line.label()))
                        .filter(line -> flagged.get(rule).contains(line)));
    }

    private static String describe(java.util.stream.Stream<Line> found) {
        return found.map(
                        line ->
                                "  "
                                        + line.file()
                                        + ":"
                                        + line.number()
                                        + " ["
                                        + (line.label().isEmpty() ? "generated" : line.label())
                                        + "] "
                                        + line.event().raw())
                .collect(Collectors.joining("\n"));
    }

    private String report() {
        StringBuilder out = new StringBuilder();
        out.append(
                String.format(
                        Locale.ROOT,
                        "%nConfusion matrix per log line: %,d lines, %,d injected (%s)%n",
                        lines.size(),
                        summary.injected(),
                        summary.injectedPerLabel()));
        out.append(
                String.format(
                        Locale.ROOT,
                        "%-20s %6s %6s %8s %6s %10s %7s %7s %6s%n",
                        "rule",
                        "TP",
                        "FP",
                        "TN",
                        "FN",
                        "precision",
                        "recall",
                        "FPR",
                        "F1"));
        matrices.forEach((rule, matrix) -> out.append(row(rule, matrix)));
        out.append(row("any rule", anyRule));
        return out.toString();
    }

    private static String row(String name, Confusion m) {
        return String.format(
                Locale.ROOT,
                "%-20s %6d %6d %8d %6d %10.4f %7.4f %7.5f %6.4f%n",
                name,
                m.tp(),
                m.fp(),
                m.tn(),
                m.fn(),
                m.precision(),
                m.recall(),
                m.falsePositiveRate(),
                m.f1());
    }
}
