package com.siem.analyzer.domain;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

public record NormalizedEvent(
        Instant timestamp,
        LogFormat format,
        String host,
        String srcIp,
        Integer srcPort,
        String user,
        String method,
        String path,
        String protocol,
        Integer status,
        Long bytes,
        String referrer,
        String userAgent,
        Severity severity,
        String message,
        String raw,
        Map<String, Object> attributes) {

    private static final String ABSENT = "-";

    public NormalizedEvent {
        Objects.requireNonNull(timestamp, "timestamp");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(raw, "raw");

        host = clean(host);
        srcIp = clean(srcIp);
        user = clean(user);
        method = clean(method);
        if (method != null) {
            method = method.toUpperCase(Locale.ROOT);
        }
        path = clean(path);
        protocol = clean(protocol);
        referrer = clean(referrer);
        userAgent = clean(userAgent);
        message = clean(message);

        requireRange("srcPort", srcPort, 0, 65_535);
        requireRange("status", status, 100, 599);
        if (bytes != null && bytes < 0) {
            throw new IllegalArgumentException("bytes must not be negative: " + bytes);
        }

        severity = severity == null ? Severity.INFO : severity;

        attributes =
                attributes == null || attributes.isEmpty()
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    public static Builder builder(Instant timestamp, LogFormat format, String raw) {
        return new Builder(timestamp, format, raw);
    }

    private static String clean(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.strip();
        return trimmed.isEmpty() || ABSENT.equals(trimmed) ? null : trimmed;
    }

    private static void requireRange(String name, Integer value, int min, int max) {
        if (value != null && (value < min || value > max)) {
            throw new IllegalArgumentException(
                    name + " must be between " + min + " and " + max + ": " + value);
        }
    }

    public static final class Builder {

        private final Instant timestamp;
        private final LogFormat format;
        private final String raw;
        private String host;
        private String srcIp;
        private Integer srcPort;
        private String user;
        private String method;
        private String path;
        private String protocol;
        private Integer status;
        private Long bytes;
        private String referrer;
        private String userAgent;
        private Severity severity;
        private String message;
        private Map<String, Object> attributes;

        private Builder(Instant timestamp, LogFormat format, String raw) {
            this.timestamp = timestamp;
            this.format = format;
            this.raw = raw;
        }

        public Builder host(String host) {
            this.host = host;
            return this;
        }

        public Builder srcIp(String srcIp) {
            this.srcIp = srcIp;
            return this;
        }

        public Builder srcPort(Integer srcPort) {
            this.srcPort = srcPort;
            return this;
        }

        public Builder user(String user) {
            this.user = user;
            return this;
        }

        public Builder method(String method) {
            this.method = method;
            return this;
        }

        public Builder path(String path) {
            this.path = path;
            return this;
        }

        public Builder protocol(String protocol) {
            this.protocol = protocol;
            return this;
        }

        public Builder status(Integer status) {
            this.status = status;
            return this;
        }

        public Builder bytes(Long bytes) {
            this.bytes = bytes;
            return this;
        }

        public Builder referrer(String referrer) {
            this.referrer = referrer;
            return this;
        }

        public Builder userAgent(String userAgent) {
            this.userAgent = userAgent;
            return this;
        }

        public Builder severity(Severity severity) {
            this.severity = severity;
            return this;
        }

        public Builder message(String message) {
            this.message = message;
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes = attributes;
            return this;
        }

        public NormalizedEvent build() {
            return new NormalizedEvent(
                    timestamp,
                    format,
                    host,
                    srcIp,
                    srcPort,
                    user,
                    method,
                    path,
                    protocol,
                    status,
                    bytes,
                    referrer,
                    userAgent,
                    severity,
                    message,
                    raw,
                    attributes);
        }
    }
}
