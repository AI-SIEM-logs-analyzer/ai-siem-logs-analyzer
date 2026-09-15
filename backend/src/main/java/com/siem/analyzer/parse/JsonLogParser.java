package com.siem.analyzer.parse;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.parse.JsonFieldMapping.Field;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.temporal.ChronoField;
import java.time.temporal.TemporalAccessor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;
import java.util.regex.Pattern;

/**
 * Parses structured JSON log lines: one JSON object per line, as NDJSON files, Filebeat, nginx
 * {@code escape=json}, pino, bunyan and Python's JSON loggers write them.
 *
 * <p>Which key feeds which field is not fixed but comes from a {@link JsonFieldMapping}, so a
 * source with its own vocabulary is onboarded with configuration instead of code. For each field
 * the first candidate path holding a value of a usable type wins. A value that cannot be used — a
 * {@code "status":"success"}, a port above 65535, an object where text is expected — is skipped
 * rather than failing the line, and the next candidate is tried.
 *
 * <p>Values that fed a field are taken out of the object, objects left empty by that are pruned,
 * and everything else becomes the event's attributes with its nesting, key order, {@code null}s and
 * number precision intact: integers as {@code Integer}, {@code Long} or {@code BigInteger},
 * decimals as {@code BigDecimal}. Nested maps and lists are read-only.
 *
 * <p>A line with no usable timestamp is still an event and is stamped with the time it was read, as
 * {@link SyslogParser} does for a nil RFC 5424 timestamp. Numeric timestamps are Unix epoch, in
 * seconds, milliseconds, microseconds or nanoseconds depending on their magnitude; text timestamps
 * are ISO 8601 in its common variants, RFC 1123 or Apache's {@code 14/Sep/2026:10:15:30 +0000}.
 *
 * <p>A line that is not exactly one JSON object yields an empty result rather than an exception, as
 * in the other parsers. So does a line with a repeated key or more than {@value #MAX_NESTING_DEPTH}
 * levels of nesting. A single JSON array spanning a whole file is not a line format and has to be
 * split by whoever reads the file. Instances are immutable and safe to share between threads.
 */
@ApplicationScoped
public class JsonLogParser {

    /**
     * Deeper than any log schema in use; ECS tops out around five. The limit is enforced while
     * reading, so a hostile line is refused before a tree of it is ever built.
     */
    static final int MAX_NESTING_DEPTH = 64;

    /**
     * A private mapper rather than the application's: a module or feature registered for the REST
     * layer must not change what a log line means.
     *
     * <p>Duplicate keys are an error because JSON leaves their meaning open, and a SIEM that reads
     * the last value while the application that wrote the line acted on the first can be told a
     * different user than the one that logged in. Trailing tokens are an error because {@code
     * {...}{...}} is two events, or a corrupt line, but not one event. Floats are read as {@code
     * BigDecimal} so that an epoch timestamp with microseconds survives to the last digit.
     */
    private static final ObjectMapper MAPPER =
            JsonMapper.builder(
                            JsonFactory.builder()
                                    .streamReadConstraints(
                                            StreamReadConstraints.builder()
                                                    .maxNestingDepth(MAX_NESTING_DEPTH)
                                                    .build())
                                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                                    .build())
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
                    .build();

    /**
     * {@code 2026-09-14T10:15:30Z} and the variants loggers actually write: a space instead of the
     * {@code T}, a comma before the fraction (Python's {@code asctime}), an offset with or without
     * its colon, or no offset at all.
     */
    private static final DateTimeFormatter ISO_LIKE =
            new DateTimeFormatterBuilder()
                    .parseCaseInsensitive()
                    .append(DateTimeFormatter.ISO_LOCAL_DATE)
                    .optionalStart()
                    .appendLiteral('T')
                    .optionalEnd()
                    .optionalStart()
                    .appendLiteral(' ')
                    .optionalEnd()
                    .appendValue(ChronoField.HOUR_OF_DAY, 2)
                    .appendLiteral(':')
                    .appendValue(ChronoField.MINUTE_OF_HOUR, 2)
                    .appendLiteral(':')
                    .appendValue(ChronoField.SECOND_OF_MINUTE, 2)
                    .optionalStart()
                    .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, true)
                    .optionalEnd()
                    .optionalStart()
                    .appendLiteral(',')
                    .appendFraction(ChronoField.NANO_OF_SECOND, 1, 9, false)
                    .optionalEnd()
                    .optionalStart()
                    .appendOffset("+HH:MM", "Z")
                    .optionalEnd()
                    .optionalStart()
                    .appendOffset("+HHMM", "Z")
                    .optionalEnd()
                    .toFormatter(Locale.ROOT);

    /** Apache's and nginx's {@code $time_local}, which nginx JSON log formats often reuse. */
    private static final DateTimeFormatter APACHE =
            DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private static final List<DateTimeFormatter> TEXT_TIMESTAMPS =
            List.of(ISO_LIKE, DateTimeFormatter.RFC_1123_DATE_TIME, APACHE);

    /** An epoch written as a JSON string. Bounded so the pattern alone rules out absurd values. */
    private static final Pattern EPOCH_TEXT = Pattern.compile("-?\\d{1,20}(?:\\.\\d{1,9})?");

    private static final Pattern DIGITS = Pattern.compile("\\d{1,18}");

    /**
     * Epoch values below this are seconds; each further factor of 1000 is the next unit down. In
     * seconds, 10^11 is the year 5138, and in milliseconds it is March 1973, so no timestamp a log
     * carries today falls on the wrong side of a boundary.
     */
    private static final BigDecimal SECONDS_BELOW = new BigDecimal("1e11");

    private static final BigDecimal MILLIS_BELOW = new BigDecimal("1e14");

    private static final BigDecimal MICROS_BELOW = new BigDecimal("1e17");

    /**
     * Largest number of digits on either side of the point a number may have to be tried as an
     * epoch. {@code 1e999999999} is a short literal but a billion-digit integer once rescaled.
     */
    private static final int MAX_EPOCH_DIGITS = 30;

    private static final Map<String, Severity> SEVERITY_WORDS =
            Map.ofEntries(
                    Map.entry("trace", Severity.DEBUG),
                    Map.entry("debug", Severity.DEBUG),
                    Map.entry("fine", Severity.DEBUG),
                    Map.entry("finer", Severity.DEBUG),
                    Map.entry("finest", Severity.DEBUG),
                    Map.entry("info", Severity.INFO),
                    Map.entry("information", Severity.INFO),
                    Map.entry("informational", Severity.INFO),
                    Map.entry("notice", Severity.INFO),
                    Map.entry("warn", Severity.WARNING),
                    Map.entry("warning", Severity.WARNING),
                    Map.entry("err", Severity.ERROR),
                    Map.entry("error", Severity.ERROR),
                    Map.entry("severe", Severity.ERROR),
                    Map.entry("crit", Severity.CRITICAL),
                    Map.entry("critical", Severity.CRITICAL),
                    Map.entry("alert", Severity.CRITICAL),
                    Map.entry("emerg", Severity.CRITICAL),
                    Map.entry("emergency", Severity.CRITICAL),
                    Map.entry("fatal", Severity.CRITICAL),
                    Map.entry("panic", Severity.CRITICAL));

    private final JsonFieldMapping mapping;
    private final Clock clock;
    private final ZoneId zone;

    @Inject
    public JsonLogParser(AppConfig config) {
        this(
                JsonFieldMapping.from(config.parse().json().fields()),
                Clock.systemUTC(),
                ZoneOffset.UTC);
    }

    /**
     * @param mapping where each standard field is looked for
     * @param clock stamps a line that carries no usable timestamp
     * @param zone the zone a text timestamp without an offset is read in
     */
    JsonLogParser(JsonFieldMapping mapping, Clock clock, ZoneId zone) {
        this.mapping = Objects.requireNonNull(mapping, "mapping");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.zone = Objects.requireNonNull(zone, "zone");
    }

    /**
     * Parses one JSON log line.
     *
     * @param line a single line, without its line terminator
     * @return the event, or empty when the line is not exactly one JSON object
     */
    public Optional<NormalizedEvent> parse(String line) {
        Objects.requireNonNull(line, "line");
        JsonNode root;
        try {
            root = MAPPER.readTree(line);
        } catch (JsonProcessingException e) {
            // Malformed, a repeated key, trailing content or too deep; StreamConstraintsException
            // is a JsonProcessingException too.
            return Optional.empty();
        }
        // An empty or blank line reads as a missing node, not as an error.
        if (!(root instanceof ObjectNode object)) {
            return Optional.empty();
        }

        Extraction fields = new Extraction(object);
        Instant timestamp =
                fields.first(Field.TIMESTAMP, this::timestamp).orElseGet(clock::instant);
        String host = fields.first(Field.HOST, JsonLogParser::text).orElse(null);
        String srcIp = fields.first(Field.SRC_IP, JsonLogParser::text).orElse(null);
        Integer srcPort =
                fields.first(Field.SRC_PORT, node -> integer(node, 0, 65_535)).orElse(null);
        String user = fields.first(Field.USER, JsonLogParser::text).orElse(null);
        String method = fields.first(Field.METHOD, JsonLogParser::text).orElse(null);
        String path = fields.first(Field.PATH, JsonLogParser::text).orElse(null);
        String protocol = fields.first(Field.PROTOCOL, JsonLogParser::text).orElse(null);
        Integer status = fields.first(Field.STATUS, node -> integer(node, 100, 599)).orElse(null);
        Long bytes = fields.first(Field.BYTES, JsonLogParser::bytes).orElse(null);
        String referrer = fields.first(Field.REFERRER, JsonLogParser::text).orElse(null);
        String userAgent = fields.first(Field.USER_AGENT, JsonLogParser::text).orElse(null);
        Severity severity = fields.first(Field.SEVERITY, JsonLogParser::severity).orElse(null);
        String message = fields.first(Field.MESSAGE, JsonLogParser::text).orElse(null);

        return Optional.of(
                NormalizedEvent.builder(timestamp, LogFormat.JSON, line)
                        .host(host)
                        .srcIp(srcIp)
                        .srcPort(srcPort)
                        .user(user)
                        .method(method)
                        .path(path)
                        .protocol(protocol)
                        .status(status)
                        .bytes(bytes)
                        .referrer(referrer)
                        .userAgent(userAgent)
                        .severity(severity)
                        .message(message)
                        .attributes(fields.remaining())
                        .build());
    }

    /**
     * One pass over one line's object: finds the value for each field, remembers where it was, and
     * hands back what no field claimed.
     */
    private final class Extraction {

        private final ObjectNode root;
        private final List<List<Step>> consumed = new ArrayList<>();

        Extraction(ObjectNode root) {
            this.root = root;
        }

        <T> Optional<T> first(Field field, Function<JsonNode, Optional<T>> coerce) {
            for (String path : mapping.paths(field)) {
                List<Step> location = locate(root, path.split("\\."), 0);
                if (location == null) {
                    continue;
                }
                Step last = location.get(location.size() - 1);
                Optional<T> value = coerce.apply(last.parent().get(last.key()));
                if (value.isPresent()) {
                    consumed.add(location);
                    return value;
                }
            }
            return Optional.empty();
        }

        /**
         * Removes every consumed value, and each object that removal empties, then converts the
         * rest. Only called once every field has been looked up, so no lookup sees a pruned tree.
         */
        Map<String, Object> remaining() {
            for (List<Step> location : consumed) {
                for (int i = location.size() - 1; i >= 0; i--) {
                    Step step = location.get(i);
                    step.parent().remove(step.key());
                    // An object that was empty in the line stays; only one emptied here goes.
                    if (!step.parent().isEmpty()) {
                        break;
                    }
                }
            }
            Map<String, Object> attributes = new LinkedHashMap<>();
            root.properties()
                    .forEach(entry -> attributes.put(entry.getKey(), toJava(entry.getValue())));
            return attributes;
        }
    }

    /** One key lookup on the way to a value: {@code parent.get(key)}. */
    private record Step(ObjectNode parent, String key) {}

    /**
     * Finds {@code segments[from..]} under {@code node}, returning the lookups from {@code node}
     * down, or {@code null}.
     *
     * <p>Longest key first: for {@code log.level} the flat key {@code "log.level"} is tried before
     * the object {@code "log"}, so a line carrying both reads the more specific one. A path has a
     * handful of segments, so trying every split costs nothing.
     */
    private static List<Step> locate(ObjectNode node, String[] segments, int from) {
        for (int end = segments.length; end > from; end--) {
            String key = String.join(".", List.of(segments).subList(from, end));
            JsonNode child = node.get(key);
            if (child == null) {
                continue;
            }
            if (end == segments.length) {
                List<Step> location = new ArrayList<>();
                location.add(new Step(node, key));
                return location;
            }
            if (child instanceof ObjectNode nested) {
                List<Step> rest = locate(nested, segments, end);
                if (rest != null) {
                    rest.add(0, new Step(node, key));
                    return rest;
                }
            }
        }
        return null;
    }

    // --- Coercion: each returns empty when the value cannot fill the field -----------------------

    /** Text, or an integer written as a number (a numeric user id). Never an object or array. */
    private static Optional<String> text(JsonNode node) {
        if (node.isTextual()) {
            return Optional.of(node.textValue());
        }
        return node.isIntegralNumber() ? Optional.of(node.asText()) : Optional.empty();
    }

    private static Optional<Integer> integer(JsonNode node, int min, int max) {
        Long value = wholeNumber(node);
        return value != null && value >= min && value <= max
                ? Optional.of(value.intValue())
                : Optional.empty();
    }

    private static Optional<Long> bytes(JsonNode node) {
        Long value = wholeNumber(node);
        return value != null && value >= 0 ? Optional.of(value) : Optional.empty();
    }

    /** A JSON integer that fits a long, or a string of digits; loggers write numbers either way. */
    private static Long wholeNumber(JsonNode node) {
        if (node.isIntegralNumber() && node.canConvertToLong()) {
            return node.longValue();
        }
        if (node.isTextual() && DIGITS.matcher(node.textValue()).matches()) {
            return Long.parseLong(node.textValue());
        }
        return null;
    }

    private Optional<Instant> timestamp(JsonNode node) {
        try {
            if (node.isNumber()) {
                return epoch(node.decimalValue());
            }
            if (!node.isTextual()) {
                return Optional.empty();
            }
            String text = node.textValue().strip();
            if (EPOCH_TEXT.matcher(text).matches()) {
                return epoch(new BigDecimal(text));
            }
            for (DateTimeFormatter formatter : TEXT_TIMESTAMPS) {
                Optional<Instant> parsed = parseText(text, formatter);
                if (parsed.isPresent()) {
                    return parsed;
                }
            }
            return Optional.empty();
        } catch (DateTimeException | ArithmeticException e) {
            // A date that does not exist or an instant outside what java.time holds.
            return Optional.empty();
        }
    }

    private Optional<Instant> parseText(String text, DateTimeFormatter formatter) {
        TemporalAccessor parsed;
        try {
            parsed = formatter.parseBest(text, OffsetDateTime::from, LocalDateTime::from);
        } catch (DateTimeException e) {
            return Optional.empty();
        }
        return Optional.of(
                parsed instanceof OffsetDateTime offset
                        ? offset.toInstant()
                        : ((LocalDateTime) parsed).atZone(zone).toInstant());
    }

    private static Optional<Instant> epoch(BigDecimal value) {
        if (value.scale() > MAX_EPOCH_DIGITS
                || value.precision() - value.scale() > MAX_EPOCH_DIGITS) {
            return Optional.empty();
        }
        BigDecimal magnitude = value.abs();
        int pointShift;
        if (magnitude.compareTo(SECONDS_BELOW) < 0) {
            pointShift = 0;
        } else if (magnitude.compareTo(MILLIS_BELOW) < 0) {
            pointShift = 3;
        } else if (magnitude.compareTo(MICROS_BELOW) < 0) {
            pointShift = 6;
        } else {
            pointShift = 9;
        }
        BigDecimal seconds = value.movePointLeft(pointShift);
        BigDecimal whole = seconds.setScale(0, RoundingMode.FLOOR);
        long nanos =
                seconds.subtract(whole)
                        .movePointRight(9)
                        .setScale(0, RoundingMode.FLOOR)
                        .longValueExact();
        return Optional.of(Instant.ofEpochSecond(whole.longValueExact(), nanos));
    }

    /**
     * Level words, case-insensitive, and two numeric scales that do not overlap: syslog's 0-7 and
     * pino's and bunyan's 10-60.
     */
    private static Optional<Severity> severity(JsonNode node) {
        Long number = wholeNumber(node);
        if (number != null) {
            return numericSeverity(number);
        }
        if (!node.isTextual()) {
            return Optional.empty();
        }
        return Optional.ofNullable(
                SEVERITY_WORDS.get(node.textValue().strip().toLowerCase(Locale.ROOT)));
    }

    private static Optional<Severity> numericSeverity(long level) {
        Severity severity =
                switch ((int) Math.min(level, Integer.MAX_VALUE)) {
                    case 0, 1, 2 -> Severity.CRITICAL;
                    case 3 -> Severity.ERROR;
                    case 4 -> Severity.WARNING;
                    case 5, 6 -> Severity.INFO;
                    case 7 -> Severity.DEBUG;
                    case 10, 20 -> Severity.DEBUG;
                    case 30 -> Severity.INFO;
                    case 40 -> Severity.WARNING;
                    case 50 -> Severity.ERROR;
                    case 60 -> Severity.CRITICAL;
                    default -> null;
                };
        return Optional.ofNullable(severity);
    }

    /** Converts what is left of the line to plain, read-only Java values. */
    private static Object toJava(JsonNode node) {
        if (node.isObject()) {
            Map<String, Object> map = new LinkedHashMap<>();
            node.properties().forEach(entry -> map.put(entry.getKey(), toJava(entry.getValue())));
            return Collections.unmodifiableMap(map);
        }
        if (node.isArray()) {
            // List.copyOf would reject the nulls a JSON array may hold.
            List<Object> list = new ArrayList<>(node.size());
            for (Iterator<JsonNode> elements = node.elements(); elements.hasNext(); ) {
                list.add(toJava(elements.next()));
            }
            return Collections.unmodifiableList(list);
        }
        if (node.isNull()) {
            return null;
        }
        if (node.isBoolean()) {
            return node.booleanValue();
        }
        if (node.isIntegralNumber()) {
            if (node.canConvertToInt()) {
                return node.intValue();
            }
            return node.canConvertToLong() ? node.longValue() : node.bigIntegerValue();
        }
        if (node.isNumber()) {
            return node.decimalValue();
        }
        return node.asText();
    }
}
