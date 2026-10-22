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

@ApplicationScoped
public class AccessLogParser {

    private static final String QUOTED_BODY = "[^\"\\\\]*+(?:\\\\.[^\"\\\\]*+)*+";

    private static final String REQUEST =
            "(?:%{WORD:method} %{NOTSPACE:path}(?: %{NOTSPACE:protocol})?|%{QUOTEDBODY})";

    private static final String CLIENT = "(?:%{IP}|[0-9A-Za-z][0-9A-Za-z.-]{0,254}+)";

    private static final String EXPRESSION =
            "^%{ACCESSCLIENT:clientip} %{NOTSPACE:ident} %{NOTSPACE:auth} \\[%{HTTPDATE:timestamp}\\]"
                    + " \"%{ACCESSREQUEST:request}\" %{INT:status} (?:%{INT:bytes}|-)"
                    + "(?: \"%{QUOTEDBODY:referrer}\" \"%{QUOTEDBODY:agent}\")?$";

    private static final DateTimeFormatter HTTP_DATE =
            DateTimeFormatter.ofPattern("dd/MMM/uuuu:HH:mm:ss Z", Locale.ENGLISH)
                    .withResolverStyle(ResolverStyle.STRICT);

    private final Grok grok;

    public AccessLogParser() {
        GrokCompiler compiler = GrokCompiler.newInstance();
        compiler.registerDefaultPatterns();
        compiler.register("QUOTEDBODY", QUOTED_BODY);
        compiler.register("ACCESSREQUEST", REQUEST);
        compiler.register("ACCESSCLIENT", CLIENT);

        this.grok = compiler.compile(EXPRESSION, true);
    }

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
                            .message(text(fields, "request"))
                            .attributes(
                                    ident == null || "-".equals(ident)
                                            ? Map.of()
                                            : Map.of("ident", ident))
                            .build();
            return Optional.of(event);
        } catch (DateTimeException | IllegalArgumentException e) {

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
