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

@ApplicationScoped
public class SyslogParser {

    private static final Pattern RFC5424_START = Pattern.compile("^<\\d{1,3}>\\d{1,2} ");

    private static final Pattern RFC5424_HEADER =
            Pattern.compile(
                    "^<(?<pri>\\d{1,3})>(?<version>\\d{1,2}) (?<timestamp>[!-~]+)"
                            + " (?<host>[!-~]{1,255}) (?<app>[!-~]{1,48}) (?<procid>[!-~]{1,128})"
                            + " (?<msgid>[!-~]{1,32}) ");

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

    private static final Pattern SSHD_LOGIN =
            Pattern.compile(
                    "^(?:(?:Failed|Accepted) \\S{1,64} for (?:invalid user )?|Invalid user )"
                            + "(?<user>.*) from "
                            + "(?<ip>\\d{1,3}(?:\\.\\d{1,3}){3}"
                            + "|(?=[0-9A-Fa-f.]{0,45}:)[0-9A-Fa-f.:]{2,45})"
                            + "(?: port (?<port>\\d{1,5}))?(?: ssh2(?:: .*)?)?\\z",
                    Pattern.DOTALL);

    private static final List<String> SSHD_TAGS = List.of("sshd", "sshd-session");

    private static final int MAX_PORT = 65_535;

    private static final List<String> MONTHS =
            List.of(
                    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                    "Dec");

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

    private static final int MAX_PRIORITY = 191;

    private static final int MAX_SD_NAME = 32;

    private static final Duration FUTURE_TOLERANCE = Duration.ofDays(1);

    private static final String NIL = "-";

    private static final char BYTE_ORDER_MARK = '\uFEFF';

    private final Clock clock;
    private final ZoneId zone;

    public SyslogParser() {
        this(Clock.systemUTC(), ZoneOffset.UTC);
    }

    SyslogParser(Clock clock, ZoneId zone) {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.zone = Objects.requireNonNull(zone, "zone");
    }

    public Optional<NormalizedEvent> parse(String line) {
        Objects.requireNonNull(line, "line");
        try {
            return RFC5424_START.matcher(line).lookingAt() ? parseRfc5424(line) : parseBsd(line);
        } catch (DateTimeException | IllegalArgumentException e) {

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

        NormalizedEvent.Builder event =
                NormalizedEvent.builder(
                                NIL.equals(timestamp)
                                        ? clock.instant()
                                        : OffsetDateTime.parse(timestamp).toInstant(),
                                LogFormat.SYSLOG,
                                line)
                        .host(header.group("host"))
                        .severity(severity(priority))
                        .message(message)
                        .attributes(attributes);
        readSshdLogin(event, header.group("app"), message);
        return Optional.of(event.build());
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

                attributes.put("timezone", tz);
            }
            timestamp = bsdTimestamp(match, utc ? ZoneOffset.UTC : zone);
        }

        putIfPresent(attributes, "appName", match.group("tag"));
        putIfPresent(attributes, "procId", match.group("pid"));

        NormalizedEvent.Builder event =
                NormalizedEvent.builder(timestamp, LogFormat.SYSLOG, line)
                        .host(match.group("host"))
                        .severity(severity)
                        .message(match.group("msg"))
                        .attributes(attributes);
        readSshdLogin(event, match.group("tag"), match.group("msg"));
        return Optional.of(event.build());
    }

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
                pos++;

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

    private static Severity severity(int priority) {
        return switch (priority % 8) {
            case 0, 1, 2 -> Severity.CRITICAL;
            case 3 -> Severity.ERROR;
            case 4 -> Severity.WARNING;
            case 5, 6 -> Severity.INFO;
            default -> Severity.DEBUG;
        };
    }

    private static void readSshdLogin(NormalizedEvent.Builder event, String tag, String message) {
        if (message == null || tag == null || !SSHD_TAGS.contains(tag)) {
            return;
        }

        Matcher login = SSHD_LOGIN.matcher(message.strip());
        if (!login.matches()) {
            return;
        }
        event.srcIp(login.group("ip")).user(login.group("user"));
        String port = login.group("port");
        if (port != null && Integer.parseInt(port) <= MAX_PORT) {
            event.srcPort(Integer.parseInt(port));
        }
    }

    private static void putIfPresent(Map<String, Object> attributes, String key, String value) {
        if (value != null && !NIL.equals(value)) {
            attributes.put(key, value);
        }
    }

    private static String stripByteOrderMark(String message) {
        return !message.isEmpty() && message.charAt(0) == BYTE_ORDER_MARK
                ? message.substring(1)
                : message;
    }
}
