package com.siem.analyzer.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.domain.LogFormat;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LogFormatDetectorTest {

    private static final int SNIFF_BYTES = 512;

    @TempDir Path tempDir;

    private LogFormatDetector detector;

    @BeforeEach
    void setUp() {
        detector = new LogFormatDetector(SNIFF_BYTES);
    }

    @Test
    void detectsJsonWhenFirstLineIsAnObject() throws IOException {
        Path file = write("events.json", "{\"ts\":\"2026-09-04T12:00:00Z\",\"msg\":\"hi\"}\n");

        assertEquals(LogFormat.JSON, detector.detect(file, "events.json"));
    }

    @Test
    void detectsJsonWhenFirstLineIsAnArray() throws IOException {
        Path file = write("events.json", "[{\"msg\":\"hi\"}]\n");

        assertEquals(LogFormat.JSON, detector.detect(file, "events.json"));
    }

    @Test
    void detectsCefFromItsPrefix() throws IOException {
        Path file =
                write(
                        "vendor.log",
                        "CEF:0|Security|threatmanager|1.0|100|worm stopped|10|src=10.0.0.1\n");

        assertEquals(LogFormat.CEF, detector.detect(file, "vendor.log"));
    }

    @Test
    void detectsSyslogFromPriorityPrefix() throws IOException {
        Path file = write("auth.log", "<34>1 2026-09-04T22:14:15.003Z host app - - - failed\n");

        assertEquals(LogFormat.SYSLOG, detector.detect(file, "auth.log"));
    }

    @Test
    void detectsSyslogFromRfc3164Timestamp() throws IOException {
        Path file = write("auth.log", "Oct 11 22:14:15 mymachine su: 'su root' failed\n");

        assertEquals(LogFormat.SYSLOG, detector.detect(file, "auth.log"));
    }

    @Test
    void detectsCsvWhenExtensionIsCsvAndDelimiterCountIsConstant() throws IOException {
        Path file = write("events.csv", "ts,host,msg\n2026-09-04,web01,started\n");

        assertEquals(LogFormat.CSV, detector.detect(file, "events.csv"));
    }

    @Test
    void returnsPlainForCsvExtensionWithInconsistentDelimiterCount() throws IOException {
        Path file = write("events.csv", "ts,host,msg\n2026-09-04,web01\n");

        assertEquals(LogFormat.PLAIN, detector.detect(file, "events.csv"));
    }

    @Test
    void returnsPlainForFreeformText() throws IOException {
        Path file = write("app.log", "starting up, nothing structured here\n");

        assertEquals(LogFormat.PLAIN, detector.detect(file, "app.log"));
    }

    @Test
    void skipsLeadingBlankLinesBeforeDeciding() throws IOException {
        Path file = write("events.json", "\n  \n{\"msg\":\"hi\"}\n");

        assertEquals(LogFormat.JSON, detector.detect(file, "events.json"));
    }

    @Test
    void detectsAccessLogFromCombinedLine() throws IOException {
        Path file =
                write(
                        "access.log",
                        "127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] \"GET /apache_pb.gif"
                                + " HTTP/1.0\" 200 2326\n");

        assertEquals(LogFormat.ACCESS_LOG, detector.detect(file, "access.log"));
    }

    @Test
    void returnsPlainWhenEveryLineIsBlank() throws IOException {
        Path file = write("empty.log", "\n\n   \n");

        assertEquals(LogFormat.PLAIN, detector.detect(file, "empty.log"));
    }

    private Path write(String name, String content) throws IOException {
        Path file = tempDir.resolve(name);
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }
}
