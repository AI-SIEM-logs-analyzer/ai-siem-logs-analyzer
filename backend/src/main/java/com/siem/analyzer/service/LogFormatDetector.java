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

@ApplicationScoped
public class LogFormatDetector {

    private static final Pattern JSON_ARRAY_START = Pattern.compile("^\\[\\s*(?:[\\[{\\]]|$)");

    private static final Pattern SYSLOG_PRIORITY = Pattern.compile("^<\\d{1,3}>");

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

    public LogFormat detect(Path filePath, String fileName) {
        List<String> lines = readHeadLines(filePath);

        String first = lines.stream().filter(line -> !line.isBlank()).findFirst().orElse(null);
        if (first == null) {
            return LogFormat.PLAIN;
        }

        String trimmed = first.strip();
        if (trimmed.startsWith("{") || JSON_ARRAY_START.matcher(trimmed).find()) {
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
