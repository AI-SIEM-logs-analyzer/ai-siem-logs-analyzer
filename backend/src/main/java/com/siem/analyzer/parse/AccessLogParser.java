package com.siem.analyzer.parse;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import io.krakens.grok.api.Grok;
import io.krakens.grok.api.GrokCompiler;
import io.krakens.grok.api.Match;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.ResolverStyle;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Parses Apache and Nginx access-log lines in Common or Combined Log Format.
 *
 * <p>Both formats are one grok expression: Combined is Common followed by the quoted referrer and
 * user agent, so those two fields are an optional tail. Nginx's default {@code combined} format
 * writes the same fields in the same order, which is why one parser covers both servers.
 *
 * <p>Fields are kept as the server wrote them. The escapes Apache and Nginx put into quoted fields
 * ({@code \"}, {@code \x16}) are not decoded, because an escaped byte in a request line is often
 * the very thing a detection rule is looking for.
 *
 * <p>A line that does not fit — another format, extra trailing fields, a date that does not exist,
 * a status outside 100-599 — yields an empty result rather than an exception. Deciding whether an
 * unparsed line is worth failing a batch over is the caller's call, not the parser's.
 *
 * <p>Instances are immutable and safe to share between threads: the compiled expression is
 * read-only, and every call gets its own matcher.
 */
@ApplicationScoped
public class AccessLogParser {

    /**
     * The inside of a double-quoted field. Both servers escape an embedded quote as {@code \"} or
     * {@code \x22}, so a backslash always consumes the character after it and a bare quote always
     * ends the field.
     *
     * <p>Written as an unrolled loop of possessive runs, not the shorter {@code (?:[^"\\]|\\.)*}.
     * java.util.regex recurses once per repetition of a group, so the short form overflows the
     * stack on a user agent a few thousand characters long — and the client chooses that length.
     * Here the group repeats once per escape, and a run of plain characters costs no stack at all.
     */
    private static final String QUOTED_BODY = "[^\"\\\\]*+(?:\\\\.[^\"\\\\]*+)*+";

    /**
     * The request line when it has the usual shape, and anything else when it does not.
     *
     * <p>The second branch is what catches TLS handshakes sent to a plain-HTTP port, port scanners
     * and timed-out connections ({@code "-"}). Those lines still carry a client address and a
     * status, so they parse; they just have no method, path or protocol.
     */
    private static final String REQUEST =
            "(?:%{WORD:method} %{NOTSPACE:path}(?: %{NOTSPACE:protocol})?|%{QUOTEDBODY})";

    /**
     * Common Log Format, then the optional Combined tail.
     *
     * <p>{@code ident} and {@code auth} use {@code NOTSPACE} rather than the stock {@code USER}
     * pattern, which rejects the {@code @} of an e-mail login. Anchored at both ends, so a line
     * with extra fields (an Nginx {@code $http_x_forwarded_for}, say) is not silently truncated.
     */
    private static final String EXPRESSION =
            "^%{IPORHOST:clientip} %{NOTSPACE:ident} %{NOTSPACE:auth} \\[%{HTTPDATE:timestamp}\\]"
                    + " \"%{ACCESSREQUEST:request}\" %{INT:status} (?:%{INT:bytes}|-)"
                    + "(?: \"%{QUOTEDBODY:referrer}\" \"%{QUOTEDBODY:agent}\")?$";

    /**
     * {@code %t} in Apache and {@code $time_local} in Nginx: {@code 10/Oct/2000:13:55:36 -0700}.
     * Month names are English whatever the server's locale. Strict resolving rejects 31 February
     * instead of rolling it into March.
     */
    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("dd/MMM/uuuu:HH:mm:ss Z", Locale.ENGLISH)
                    .withResolverStyle(ResolverStyle.STRICT);

    private final Grok grok;

    public AccessLogParser() {
        GrokCompiler compiler = GrokCompiler.newInstance();
        compiler.registerDefaultPatterns();
        compiler.register("QUOTEDBODY", QUOTED_BODY);
        compiler.register("ACCESSREQUEST", REQUEST);
        // Named-only keeps the captures to the fields above, not every sub-pattern of HTTPDATE.
        this.grok = compiler.compile(EXPRESSION, true);
    }

    /**
     * Parses one access-log line.
     *
     * @param line a single line, without its line terminator
     * @return the event, or empty when the line is not a valid Common or Combined Log Format line
     */
    public Optional<NormalizedEvent> parse(String line) {
        Objects.requireNonNull(line, "line");

        Match match = grok.match(line);
        if (match.isNull()) {
            return Optional.empty();
        }
        Map<String, Object> fields = match.capture();

        try {
            String ident = text(fields, "ident");
            NormalizedEvent event =
                    NormalizedEvent.builder(
                                    timestamp(text(fields, "timestamp")),
                                    LogFormat.ACCESS_LOG,
                                    line)
                            .srcIp(text(fields, "clientip"))
                            .user(text(fields, "auth"))
                            .method(text(fields, "method"))
                            .path(text(fields, "path"))
                            .protocol(text(fields, "protocol"))
                            .status(Integer.valueOf(text(fields, "status")))
                            .bytes(number(text(fields, "bytes")))
                            .referrer(text(fields, "referrer"))
                            .userAgent(text(fields, "agent"))
                            // The request line as a whole is the most useful one-line summary,
                            // and the only place an unparseable request survives.
                            .message(text(fields, "request"))
                            // RFC 1413 identd is almost never enabled, so this is nearly always
                            // "-". When it is not, it has no standard slot.
                            .attributes(
                                    ident == null || "-".equals(ident)
                                            ? Map.of()
                                            : Map.of("ident", ident))
                            .build();
            return Optional.of(event);
        } catch (DateTimeException | IllegalArgumentException e) {
            // The shape matched but a value is impossible: 31/Feb, status 999, a byte count wider
            // than a long (NumberFormatException is an IllegalArgumentException).
            return Optional.empty();
        }
    }

    private static String text(Map<String, Object> fields, String name) {
        Object value = fields.get(name);
        return value == null ? null : value.toString();
    }

    private static Instant timestamp(String value) {
        return OffsetDateTime.parse(value, HTTP_DATE).toInstant();
    }

    private static Long number(String value) {
        return value == null ? null : Long.valueOf(value);
    }
}
