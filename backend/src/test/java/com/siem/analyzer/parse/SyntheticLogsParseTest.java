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

        Map<String, Long> files = summary.linesPerFile();
        for (Map.Entry<String, Long> file : files.entrySet()) {
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
