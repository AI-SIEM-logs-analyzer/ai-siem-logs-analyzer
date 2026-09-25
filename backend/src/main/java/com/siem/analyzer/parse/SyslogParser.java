package com.siem.analyzer.parse;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import com.siem.analyzer.domain.Severity;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses syslog lines: RFC 5424, and the BSD format of RFC 3164 in the variants Linux hosts and
 * network gear actually write.
 *
 * <p>The BSD side covers
 *
 * <ul>
 *   <li>files written by rsyslog or syslog-ng, with no priority ({@code Sep 14 10:15:30 web-01
 *       sshd[42]: ...}), in the traditional or the RFC 3339 high-precision timestamp;
 *   <li>lines received on the wire, with the {@code <PRI>} in front;
 *   <li>Cisco IOS and ASA, which add a sequence number, a {@code *} for an unsynchronised clock,
 *       milliseconds, a year or a time-zone name, and usually no host name.
 * </ul>
 *
 * <p>Syslog-specific fields with no standard slot go into the attributes under the same keys for
 * both formats: {@code facility} and {@code syslogSeverity} (the keyword, since {@link Severity}
 * folds notice into info), {@code appName} (the BSD tag), {@code procId}, {@code msgId}, {@code
 * structuredData}, {@code sequence} and {@code timezone}. A key is absent when the line has no
 * value for it.
 *
 * <p>A line that does not fit yields an empty result rather than an exception, as in {@link
 * AccessLogParser}. Instances are immutable and safe to share between threads.
 */
@ApplicationScoped
public class SyslogParser {

    /** {@code <PRI>VERSION SP}: enough to tell RFC 5424 from a BSD line, which never has it. */
    private static final Pattern RFC5424_START = Pattern.compile("^<\\d{1,3}>\\d{1,2} ");

    /**
     * The RFC 5424 header up to STRUCTURED-DATA. Every field is printable US-ASCII with the RFC's
     * length limit; {@code -} is the nil value. Structured data is not in the expression: its
     * quoted values need a scanner, see {@link #readStructuredData}.
     */
    private static final Pattern RFC5424_HEADER =
            Pattern.compile(
                    "^<(?<pri>\\d{1,3})>(?<version>\\d{1,2}) (?<timestamp>[!-~]+)"
                            + " (?<host>[!-~]{1,255}) (?<app>[!-~]{1,48}) (?<procid>[!-~]{1,128})"
                            + " (?<msgid>[!-~]{1,32}) ");

    /**
     * A BSD line, from the optional priority to the end.
     *
     * <p>The host is optional because Cisco and some relays omit it. It is told apart from the tag
     * by shape: a host never contains {@code [} and never ends in {@code :}, and a tag always is
     * followed by one of the two. {@code kernel: ...} is therefore a tag with no host, and {@code
     * web-01 kernel: ...} is both. A line with neither a host nor a tag has its first word read as
     * the host, which is also what RFC 3164 tells a relay to do.
     *
     * <p>The time-zone name is only taken when a colon follows it, as Cisco writes it; otherwise an
     * upper-case host name ({@code FW01}) would be read as a zone.
     *
     * <p>No group here repeats, so the message costs no stack however long the sender makes it.
     */
    private static final Pattern BSD =
            Pattern.compile(
                    "^(?:<(?<pri>\\d{1,3})>)?(?:(?<seq>\\d{1,10}): )?[*.]?"
                            + "(?:(?<iso>\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?"
                            + "(?:Z|[+-]\\d{2}:\\d{2}))"
                            + "|(?<month>[A-Z][a-z]{2}) {1,2}(?<day>\\d{1,2})(?: (?<year>\\d{4}))?"
                            + " (?<time>\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?)"
                            + "(?: (?<tz>[A-Z]{3,5})(?=:))?)"
                            + ":? (?:(?<host>[^\\s\\[]{0,254}[^\\s\\[:]) )?"
                            + "(?:(?<tag>[^\\s\\[:]{1,48})(?:\\[(?<pid>[^\\]\\s]{1,128})\\])?:(?: |$))?"
                            + "(?<msg>.*)$",
                    Pattern.DOTALL);

    private static final List<String> MONTHS =
            List.of(
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec");

    /** Facility codes 0-23 by the names rsyslog uses in its configuration. */
    private static final List<String> FACILITIES =
            List.of(
                    "kern",
                    "user",
                    "mail",
                    "daemon",
                    "auth",
                    "syslog",
                    "lpr",
                    "news",
                    "uucp",
                    "cron",
                    "authpriv",
                    "ftp",
                    "ntp",
                    "security",
                    "console",
                    "solaris-cron",
                    "local0",
                    "local1",
                    "local2",
                    "local3",
                    "local4",
                    "local5",
                    "local6",
                    "local7");

    private static final List<String> SEVERITY_NAMES =
            List.of("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug");

    /** The largest valid priority: facility local7 (23) times eight, plus debug (7). */
    private static final int MAX_PRIORITY = 191;

    /** RFC 5424 limits SD-IDs and parameter names to 32 characters. */
    private static final int MAX_SD_NAME = 32;

    /**
     * How far past "now" a year-less BSD timestamp may land before it is taken to be last year's. A
     * day absorbs a device clock or zone setting that is a few hours off.
     */
    private static final Duration FUTURE_TOLERANCE = Duration.ofDays(1);

    private static final String NIL = "-";

    private static final char BYTE_ORDER_MARK = '\uFEFF';

    private final Clock clock;
    private final ZoneId zone;

    public SyslogParser() {
        this(Clock.systemUTC(), ZoneOffset.UTC);
    }

    /**
     * @param clock supplies the year a BSD timestamp leaves out, and the time of an RFC 5424 line
     *     whose timestamp is nil
     * @param zone the zone a BSD timestamp without an offset is read in. RFC 3164 times are the
     *     sender's local time and the line does not say which zone that is.
     */
    SyslogParser(Clock clock, ZoneId zone) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.zone = Objects.requireNonNull(zone, "zone");
    }

    /**
     * Parses one syslog line.
     *
     * @param line a single line, without its line terminator
     * @return the event, or empty when the line is not a valid RFC 5424 or BSD syslog line
     */
    public Optional<NormalizedEvent> parse(String line) {
        Objects.requireNonNull(line, "line");
        try {
            return RFC5424_START.matcher(line).lookingAt() ? parseRfc5424(line) : parseBsd(line);
        } catch (DateTimeException | IllegalArgumentException e) {
            // The shape matched but a value is impossible: 30 February, an hour of 25, a year
            // outside what java.time accepts.
            return Optional.empty();
        }
    }

    private Optional<NormalizedEvent> parseRfc5424(String line) {
        Matcher header = RFC5424_HEADER.matcher(line);
        if (!header.lookingAt() || !"1".equals(header.group("version"))) {
            return Optional.empty();
        }
        int priority = Integer.parseInt(header.group("pri"));
        if (priority > MAX_PRIORITY) {
            return Optional.empty();
        }

        Map<String, Map<String, List<String>>> structuredData = new LinkedHashMap<>();
        int end = readStructuredData(line, header.end(), structuredData);
        if (end < 0) {
            return Optional.empty();
        }
        String message;
        if (end == line.length()) {
            message = null;
        } else if (line.charAt(end) == ' ') {
            message = stripByteOrderMark(line.substring(end + 1));
        } else {
            return Optional.empty();
        }

        String timestamp = header.group("timestamp");
        Map<String, Object> attributes = priorityAttributes(priority);
        putIfPresent(attributes, "appName", header.group("app"));
        putIfPresent(attributes, "procId", header.group("procid"));
        putIfPresent(attributes, "msgId", header.group("msgid"));
        if (!structuredData.isEmpty()) {
            attributes.put("structuredData", freeze(structuredData));
        }

        return Optional.of(
                NormalizedEvent.builder(
                                // A nil timestamp is legal: the sender had no clock. The time we
                                // read the line is the closest thing to when it happened.
                                NIL.equals(timestamp)
                                        ? clock.instant()
                                        : OffsetDateTime.parse(timestamp).toInstant(),
                                LogFormat.SYSLOG,
                                line)
                        .host(header.group("host"))
                        .severity(severity(priority))
                        .message(message)
                        .attributes(attributes)
                        .build());
    }

    private Optional<NormalizedEvent> parseBsd(String line) {
        Matcher match = BSD.matcher(line);
        if (!match.matches()) {
            return Optional.empty();
        }

        Map<String, Object> attributes;
        Severity severity;
        String pri = match.group("pri");
        if (pri == null) {
            // Files written by a local daemon drop the priority. The line says nothing about
            // severity, so it gets the default rather than a guess.
            attributes = new LinkedHashMap<>();
            severity = null;
        } else {
            int priority = Integer.parseInt(pri);
            if (priority > MAX_PRIORITY) {
                return Optional.empty();
            }
            attributes = priorityAttributes(priority);
            severity = severity(priority);
        }
        putIfPresent(attributes, "sequence", match.group("seq"));

        Instant timestamp;
        if (match.group("iso") != null) {
            timestamp = OffsetDateTime.parse(match.group("iso")).toInstant();
        } else {
            String tz = match.group("tz");
            boolean utc = "UTC".equals(tz) || "GMT".equals(tz);
            if (tz != null && !utc) {
                // Abbreviations are ambiguous (IST is India, Ireland and Israel), so the name is
                // kept for an analyst and the configured zone is used.
                attributes.put("timezone", tz);
            }
            timestamp = bsdTimestamp(match, utc ? ZoneOffset.UTC : zone);
        }

        putIfPresent(attributes, "appName", match.group("tag"));
        putIfPresent(attributes, "procId", match.group("pid"));

        return Optional.of(
                NormalizedEvent.builder(timestamp, LogFormat.SYSLOG, line)
                        .host(match.group("host"))
                        .severity(severity)
                        .message(match.group("msg"))
                        .attributes(attributes)
                        .build());
    }

    /**
     * Resolves {@code Mmm dd [yyyy] hh:mm:ss[.fff]} to an instant.
     *
     * <p>Without a year, this year is assumed unless that puts the event in the future, in which
     * case it is last year's: December lines read in January. Trying last year also rescues 29
     * February when this year is not a leap year.
     */
    private Instant bsdTimestamp(Matcher match, ZoneId timestampZone) {
        int month = MONTHS.indexOf(match.group("month")) + 1;
        if (month == 0) {
            throw new DateTimeException("Unknown month: " + match.group("month"));
        }
        int day = Integer.parseInt(match.group("day"));
        LocalTime time = LocalTime.parse(match.group("time"));

        String year = match.group("year");
        if (year != null) {
            return ZonedDateTime.of(
                            LocalDate.of(Integer.parseInt(year), month, day), time, timestampZone)
                    .toInstant();
        }

        Instant now = clock.instant();
        int thisYear = now.atZone(timestampZone).getYear();
        for (int candidateYear = thisYear; candidateYear >= thisYear - 1; candidateYear--) {
            LocalDate date;
            try {
                date = LocalDate.of(candidateYear, month, day);
            } catch (DateTimeException e) {
                continue;
            }
            Instant candidate = ZonedDateTime.of(date, time, timestampZone).toInstant();
            if (!candidate.isAfter(now.plus(FUTURE_TOLERANCE))) {
                return candidate;
            }
        }
        throw new DateTimeException("No recent year fits " + month + "/" + day);
    }

    /**
     * Reads RFC 5424 STRUCTURED-DATA starting at {@code start} into {@code into}.
     *
     * <p>A hand-written scanner rather than a regex: a quoted value may hold escaped quotes and
     * brackets, and a regex loop over its characters recurses once per character in
     * java.util.regex, which a sender can overflow with one long value. This loop is flat.
     *
     * <p>The escapes RFC 5424 defines ({@code \"}, {@code \\}, {@code \]}) are decoded, because the
     * RFC makes them part of the encoding, not the data; any other backslash is kept, as the RFC
     * requires. An unescaped {@code ]} inside a value is accepted, as rsyslog accepts it.
     *
     * <p>Every parameter collects all of its values, in order; {@link #freeze} decides afterwards
     * whether that is one value or a list. Building the list as it grows keeps a line that repeats
     * one parameter a hundred thousand times linear rather than quadratic.
     *
     * @return the index just past the field, or -1 when it is malformed
     */
    private static int readStructuredData(
            String line, int start, Map<String, Map<String, List<String>>> into) {
        int length = line.length();
        if (start < length && line.charAt(start) == '-') {
            return start + 1;
        }
        if (start >= length || line.charAt(start) != '[') {
            return -1;
        }

        int pos = start;
        while (pos < length && line.charAt(pos) == '[') {
            int idStart = pos + 1;
            int idEnd = nameEnd(line, idStart);
            if (idEnd == idStart || idEnd - idStart > MAX_SD_NAME) {
                return -1;
            }
            Map<String, List<String>> params =
                    into.computeIfAbsent(
                            line.substring(idStart, idEnd), id -> new LinkedHashMap<>());
            pos = idEnd;

            while (pos < length && line.charAt(pos) == ' ') {
                int nameStart = pos + 1;
                int nameEnd = nameEnd(line, nameStart);
                if (nameEnd == nameStart
                        || nameEnd - nameStart > MAX_SD_NAME
                        || !line.startsWith("=\"", nameEnd)) {
                    return -1;
                }

                StringBuilder value = new StringBuilder();
                pos = nameEnd + 2;
                while (pos < length && line.charAt(pos) != '"') {
                    char c = line.charAt(pos);
                    if (c == '\\' && pos + 1 < length && isEscaped(line.charAt(pos + 1))) {
                        value.append(line.charAt(pos + 1));
                        pos += 2;
                    } else {
                        value.append(c);
                        pos++;
                    }
                }
                if (pos >= length) {
                    return -1;
                }
                pos++; // the closing quote

                params.computeIfAbsent(
                                line.substring(nameStart, nameEnd), name -> new ArrayList<>())
                        .add(value.toString());
            }

            if (pos >= length || line.charAt(pos) != ']') {
                return -1;
            }
            pos++;
        }
        return pos;
    }

    /** SD-NAME: printable US-ASCII except {@code =}, space, {@code ]} and {@code "}. */
    private static int nameEnd(String line, int start) {
        int pos = start;
        while (pos < line.length()) {
            char c = line.charAt(pos);
            if (c < '!' || c > '~' || c == '=' || c == ']' || c == '"') {
                break;
            }
            pos++;
        }
        return pos;
    }

    private static boolean isEscaped(char c) {
        return c == '"' || c == '\\' || c == ']';
    }

    /**
     * The read-only attribute value for the structured data: a parameter that appears once is its
     * value, one that appears more than once in an element is the list of its values, in order.
     */
    private static Map<String, Object> freeze(Map<String, Map<String, List<String>>> elements) {
        Map<String, Object> frozen = new LinkedHashMap<>();
        elements.forEach(
                (id, params) -> {
                    Map<String, Object> values = new LinkedHashMap<>();
                    params.forEach(
                            (name, all) ->
                                    values.put(
                                            name,
                                            all.size() == 1 ? all.getFirst() : List.copyOf(all)));
                    frozen.put(id, Collections.unmodifiableMap(values));
                });
        return Collections.unmodifiableMap(frozen);
    }

    private static Map<String, Object> priorityAttributes(int priority) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("facility", FACILITIES.get(priority / 8));
        attributes.put("syslogSeverity", SEVERITY_NAMES.get(priority % 8));
        return attributes;
    }

    /** emerg, alert and crit are all CRITICAL; notice is INFO. */
    private static Severity severity(int priority) {
        return switch (priority % 8) {
            case 0, 1, 2 -> Severity.CRITICAL;
            case 3 -> Severity.ERROR;
            case 4 -> Severity.WARNING;
            case 5, 6 -> Severity.INFO;
            default -> Severity.DEBUG;
        };
    }

    private static void putIfPresent(Map<String, Object> attributes, String key, String value) {
        if (value != null && !NIL.equals(value)) {
            attributes.put(key, value);
        }
    }

    /** RFC 5424 marks a UTF-8 MSG with a leading BOM; it is encoding, not text. */
    private static String stripByteOrderMark(String message) {
        return !message.isEmpty() && message.charAt(0) == BYTE_ORDER_MARK
                ? message.substring(1)
                : message;
    }
}
