package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.parse.AccessLogParser;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Decides which log format an accepted upload holds.
 *
 * <p>Runs after {@link LogUploadValidator}, so the content is already known to be text. Only the
 * leading bytes are read, for the same reason the validator reads only the head: a file whose first
 * lines are JSON does not turn into syslog halfway down, and reading the whole body to be sure
 * would cost as much as the ingestion itself.
 *
 * <p>The result is a hint for the ingestion parser, never a gate — every branch ends at {@link
 * LogFormat#PLAIN} rather than at a rejection, because an unrecognised shape is still a log file.
 */
@ApplicationScoped
public class LogFormatDetector {

    /** RFC 5424 and RFC 3164 both start with the priority in angle brackets, when it is present. */
    private static final Pattern SYSLOG_PRIORITY = Pattern.compile("^<\\d{1,3}>");

    /** RFC 3164 without a priority: "Oct 11 22:14:15", the day space-padded to two columns. */
    private static final Pattern SYSLOG_RFC3164_TIMESTAMP =
            Pattern.compile("^[A-Z][a-z]{2} [ \\d]\\d \\d{2}:\\d{2}:\\d{2}\\b");

    private final int sniffBytes;
    private final AccessLogParser accessLogParser;

    @Inject
    public LogFormatDetector(AppConfig config, AccessLogParser accessLogParser) {
        this(config.upload().sniffBytes(), accessLogParser);
    }

    public LogFormatDetector(int sniffBytes) {
        this(sniffBytes, new AccessLogParser());
    }

    public LogFormatDetector(int sniffBytes, AccessLogParser accessLogParser) {
        this.sniffBytes = sniffBytes;
        this.accessLogParser = Objects.requireNonNull(accessLogParser, "accessLogParser");
    }

    /**
     * Detects the format of one stored log file.
     *
     * @param filePath the file to inspect
     * @param fileName the name the client gave the part, used only for the CSV extension hint
     * @return the detected format, {@link LogFormat#PLAIN} when nothing else matches
     */
    public LogFormat detect(Path filePath, String fileName) {
        List<String> lines = readHeadLines(filePath);

        String first = lines.stream().filter(line -> !line.isBlank()).findFirst().orElse(null);
        if (first == null) {
            return LogFormat.PLAIN;
        }

        String trimmed = first.strip();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            return LogFormat.JSON;
        }
        if (trimmed.startsWith("CEF:")) {
            return LogFormat.CEF;
        }
        if (SYSLOG_PRIORITY.matcher(trimmed).find()
                || SYSLOG_RFC3164_TIMESTAMP.matcher(trimmed).find()) {
            return LogFormat.SYSLOG;
        }
        if (accessLogParser.parse(trimmed).isPresent()) {
            return LogFormat.ACCESS_LOG;
        }
        if (hasCsvExtension(fileName) && hasConstantCommaCount(lines)) {
            return LogFormat.CSV;
        }
        return LogFormat.PLAIN;
    }

    /**
     * Reads the head of the file as UTF-8 lines.
     *
     * <p>When the read fills the buffer the last line is almost certainly cut mid-way, so it is
     * dropped: a truncated line has the wrong field count and would make a valid CSV look ragged.
     */
    private List<String> readHeadLines(Path filePath) {
        byte[] head = new byte[sniffBytes];
        int read;
        try (InputStream in = Files.newInputStream(filePath)) {
            read = in.readNBytes(head, 0, sniffBytes);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read uploaded file", e);
        }

        String text = new String(head, 0, Math.max(read, 0), StandardCharsets.UTF_8);
        List<String> lines = new ArrayList<>(List.of(text.split("\n", -1)));

        // The trailing element is either the empty string after a final newline or a partial line.
        // Neither carries information, so both go.
        if (!lines.isEmpty()) {
            lines.removeLast();
        }
        return lines.stream()
                .map(line -> line.endsWith("\r") ? line.substring(0, line.length() - 1) : line)
                .toList();
    }

    private static boolean hasCsvExtension(String fileName) {
        if (fileName == null) {
            return false;
        }
        return fileName.toLowerCase(Locale.ROOT).endsWith(".csv");
    }

    /**
     * A CSV needs at least a header and one record, both with the same number of separators. One
     * line alone is consistent with anything, and a ragged count means the commas are prose.
     */
    private static boolean hasConstantCommaCount(List<String> lines) {
        List<String> records = lines.stream().filter(line -> !line.isBlank()).toList();
        if (records.size() < 2) {
            return false;
        }

        long expected = commaCount(records.getFirst());
        if (expected == 0) {
            return false;
        }
        return records.stream().allMatch(line -> commaCount(line) == expected);
    }

    private static long commaCount(String line) {
        return line.chars().filter(c -> c == ',').count();
    }
}
