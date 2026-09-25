package com.siem.analyzer.parse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.loadgen.SyntheticLogGenerator;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Options;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Stream;
import com.siem.analyzer.loadgen.SyntheticLogGenerator.Summary;
import com.siem.analyzer.service.LogFormatDetector;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Proves that every line the synthetic generator writes is accepted by the production parsers, so a
 * load test measures ingestion rather than the fallback path for unparsed lines.
 */
class SyntheticLogsParseTest {

    private static final Instant START = Instant.parse("2026-09-24T00:00:00Z");

    private final AccessLogParser accessParser = new AccessLogParser();
    private final SyslogParser syslogParser = new SyslogParser();
    private final JsonLogParser jsonParser =
            new JsonLogParser(
                    JsonFieldMapping.defaults(),
                    Clock.fixed(START.plus(Duration.ofDays(1)), ZoneOffset.UTC),
                    ZoneOffset.UTC);
    private final LogFormatDetector detector = new LogFormatDetector(8192);

    @Test
    void defaultVolumeParsesCompletelyInEveryStream(@TempDir Path dir) throws IOException {
        Summary summary = SyntheticLogGenerator.generate(options(dir, 100_000, 42));

        assertEquals(100_000, summary.events());
        assertEquals(
                100_000L,
                summary.linesPerStream().values().stream().mapToLong(Long::longValue).sum());
        assertTrue(Files.exists(dir.resolve("manifest.json")));

        assertEveryLineParsesInOrder(dir, summary);
    }

    @Test
    void injectedFilesLandOnceInTheirStreamsAndGroundTruthPointsAtThem(@TempDir Path dir)
            throws IOException {
        Path inject = sampleScenarios(dir.resolve("inject"));
        Path out = dir.resolve("out");

        Summary summary = SyntheticLogGenerator.generate(withInjection(out, 2_000, inject, -1));

        assertEquals(2_000, summary.events());
        assertEquals(6, summary.injected());
        assertEquals(Map.of("sample-web", 3L, "sample-host", 3L), summary.injectedPerLabel());
        assertTrue(
                Files.readString(out.resolve("manifest.json"))
                        .contains("\"injectSkippedLines\": 1"));
        assertEveryLineParsesInOrder(out, summary);

        List<String> truth = Files.readAllLines(out.resolve("ground-truth.csv"));
        assertEquals("file,line,timestamp,label,instance,origin", truth.getFirst());
        assertEquals(7, truth.size());
        Map<String, Instant> landedAt = new java.util.HashMap<>();
        for (String row : truth.subList(1, truth.size())) {
            String[] cells = row.split(",");
            String written =
                    Files.readAllLines(out.resolve(cells[0])).get(Integer.parseInt(cells[1]) - 1);
            String marker = written.replaceAll(".*(marker-\\d).*", "$1");
            assertTrue(written.contains(marker), row);
            Instant at = Instant.parse(cells[2]);
            assertTrue(!at.isBefore(START) && at.isBefore(START.plus(Duration.ofDays(1))), row);
            landedAt.put(marker, at);
        }
        // The file is moved as a whole: lines keep their distance from each other.
        assertEquals(
                Duration.ofSeconds(90),
                Duration.between(landedAt.get("marker-1"), landedAt.get("marker-3")));
        assertEquals(
                Duration.ofSeconds(5),
                Duration.between(landedAt.get("marker-4"), landedAt.get("marker-5")));
    }

    @Test
    void injectRatioRepeatsTheFilesUntilTheShareIsReached(@TempDir Path dir) throws IOException {
        Path inject = sampleScenarios(dir.resolve("inject"));
        Path out = dir.resolve("out");

        Summary summary = SyntheticLogGenerator.generate(withInjection(out, 10_000, inject, 0.05));

        assertEquals(10_000, summary.events());
        assertEquals(500, summary.injected());
        assertEquals(2, summary.injectedPerLabel().size());
        assertEquals(501, Files.readAllLines(out.resolve("ground-truth.csv")).size());
        assertEveryLineParsesInOrder(out, summary);
    }

    @Test
    void sameSeedWritesIdenticalFiles(@TempDir Path first, @TempDir Path second)
            throws IOException {
        Summary a = SyntheticLogGenerator.generate(options(first, 5_000, 7));
        Summary b = SyntheticLogGenerator.generate(options(second, 5_000, 7));

        assertEquals(a, b);
        for (String file : a.linesPerFile().keySet()) {
            assertEquals(
                    Files.readString(first.resolve(file)), Files.readString(second.resolve(file)));
        }
    }

    @Test
    void filesRollOverBeforeTheSizeLimit(@TempDir Path dir) throws IOException {
        long limit = 64 * 1024;
        Options options =
                new Options(
                        5_000,
                        dir,
                        1,
                        START,
                        Duration.ofHours(2),
                        EnumSet.of(Stream.ACCESS),
                        limit);

        Summary summary = SyntheticLogGenerator.generate(options);

        assertTrue(summary.linesPerFile().size() > 1, "expected several access files");
        for (String file : summary.linesPerFile().keySet()) {
            assertTrue(Files.size(dir.resolve(file)) <= limit, file);
        }
    }

    private void assertEveryLineParsesInOrder(Path dir, Summary summary) throws IOException {
        for (Map.Entry<String, Long> file : summary.linesPerFile().entrySet()) {
            Path path = dir.resolve(file.getKey());
            List<String> lines = Files.readAllLines(path);
            assertEquals(file.getValue(), (long) lines.size(), file.getKey());

            LogFormat format = detector.detect(path, file.getKey());
            Function<String, Optional<NormalizedEvent>> parser =
                    switch (format) {
                        case ACCESS_LOG -> accessParser::parse;
                        case SYSLOG -> syslogParser::parse;
                        case JSON -> jsonParser::parse;
                        default -> throw new AssertionError(file.getKey() + " read as " + format);
                    };

            Instant previous = Instant.MIN;
            for (String line : lines) {
                NormalizedEvent event =
                        parser.apply(line)
                                .orElseThrow(() -> new AssertionError("unparsed: " + line));
                assertTrue(!event.timestamp().isBefore(previous), "out of order: " + line);
                assertTrue(!event.timestamp().isBefore(START), "before the span: " + line);
                previous = event.timestamp();
            }
        }
    }

    /**
     * Two small files, one per label, in every shape the injector reads, from years before the
     * span. Each line carries a marker so the ground truth can be checked against the output.
     */
    private static Path sampleScenarios(Path dir) throws IOException {
        Files.createDirectories(dir);
        Files.writeString(
                dir.resolve("sample-web.log"),
                String.join(
                        "\n",
                        "198.51.100.7 - - [03/Mar/2020:10:00:00 +0000] \"GET /marker-1 HTTP/1.1\" 200 10"
                                + " \"-\" \"curl/8.5.0\"",
                        "198.51.100.7 - - [03/Mar/2020:10:00:30 +0000] \"GET /marker-2 HTTP/1.1\" 200 10"
                                + " \"-\" \"curl/8.5.0\"",
                        "",
                        "198.51.100.7 - - [03/Mar/2020:10:01:30 +0000] \"GET /marker-3 HTTP/1.1\" 200 10"
                                + " \"-\" \"curl/8.5.0\"",
                        "this line is in no known format"));
        Files.writeString(
                dir.resolve("sample-host.ndjson"),
                String.join(
                        "\n",
                        "Mar  3 10:00:00 lab-01 maintenance[7]: marker-4 window opened",
                        "<14>1 2020-03-03T10:00:05Z lab-01 maintenance 7 - - marker-5 done",
                        "{\"message\":\"marker-6 without a timestamp\",\"host\":{\"name\":\"lab-01\"}}"));
        // The label comes from the file name, whatever the extension says about the format.
        Files.move(dir.resolve("sample-host.ndjson"), dir.resolve("sample-host.txt"));
        return dir;
    }

    private static Options withInjection(Path dir, long events, Path inject, double ratio) {
        return new Options(
                events,
                dir,
                3,
                START,
                Duration.ofDays(1),
                EnumSet.allOf(Stream.class),
                Options.DEFAULT_MAX_FILE_BYTES,
                inject,
                ratio);
    }

    private static Options options(Path dir, long events, long seed) {
        return new Options(
                events,
                dir,
                seed,
                START,
                Duration.ofDays(1),
                EnumSet.allOf(Stream.class),
                Options.DEFAULT_MAX_FILE_BYTES);
    }
}
