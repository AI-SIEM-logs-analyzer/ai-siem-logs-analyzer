package com.siem.analyzer.domain;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

/**
 * One log line in the shape every parser produces, whatever format it was read from.
 *
 * <p>This is the contract between parsing and everything downstream of it: detection rules, feature
 * extraction and persistence read these fields and never branch on {@link LogFormat}. A parser that
 * learns a new format fills the same fields; a field a format does not carry stays {@code null}.
 *
 * <p>Only {@link #timestamp}, {@link #format} and {@link #raw} are required. Everything else is
 * optional, because a free-form line may give us nothing but its text. Values that do not fit a
 * standard field go into {@link #attributes} instead of being dropped.
 *
 * <p>Optional text is normalized on construction: surrounding whitespace is trimmed, and a blank
 * value or the lone {@code -} that access logs write for "absent" becomes {@code null}. That way a
 * rule asks {@code srcIp() == null} and never has to know which placeholder a format uses. {@link
 * #raw} is the exception and is kept byte for byte, for the reason given on {@link
 * LogEvent#getRaw}.
 *
 * @param timestamp when the event happened, as reported by the source
 * @param format the wire format the line was parsed from
 * @param host the machine that emitted the line
 * @param srcIp the client or source address, as written in the log; not resolved or validated
 * @param srcPort the source port, 0-65535
 * @param user the authenticated or claimed user name
 * @param method the HTTP method, upper-cased
 * @param path the request path, query string included when the log has one
 * @param protocol the protocol token, for example {@code HTTP/1.1}
 * @param status the HTTP status code, 100-599
 * @param bytes the response size in bytes, never negative
 * @param referrer the HTTP referrer
 * @param userAgent the HTTP user agent
 * @param severity how serious the event is; {@link Severity#INFO} when the source does not say
 * @param message a short human-readable summary
 * @param raw the original line, exactly as received
 * @param attributes format-specific fields with no standard slot; read-only, never {@code null}
 */
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

    /** The placeholder access logs write for a field they have no value for. */
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

        // Map.copyOf would reject the null values JSON logs legitimately carry, and would lose
        // the source's field order, which is worth keeping when the attributes are displayed.
        attributes =
                attributes == null || attributes.isEmpty()
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    /** Starts an event from the three fields every parser can always supply. */
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

    /**
     * Assembles an event field by field.
     *
     * <p>Seventeen positional arguments are an invitation to swap two strings, so parsers should
     * build through this instead of calling the canonical constructor. Validation still happens in
     * that constructor, when {@link #build()} runs.
     */
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

        /**
         * Creates the event.
         *
         * @throws NullPointerException the timestamp, format or raw line is missing
         * @throws IllegalArgumentException a number is outside its valid range
         */
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
