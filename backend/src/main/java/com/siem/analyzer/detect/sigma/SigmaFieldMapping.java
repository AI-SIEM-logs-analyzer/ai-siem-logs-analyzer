package com.siem.analyzer.detect.sigma;

import com.siem.analyzer.detect.Condition;
import com.siem.analyzer.detect.EventField;
import com.siem.analyzer.detect.RuleExpression;
import com.siem.analyzer.detect.RuleExpressionParser;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public record SigmaFieldMapping(Map<String, String> fields, List<LogsourceMapping> logsources) {

    private static final Pattern ATTRIBUTE_KEY = Pattern.compile("[\\p{L}_][\\p{L}\\p{Nd}_.\\-]*+");

    static final String HTTP_REQUEST = "method exists";

    static final String SYSLOG = "format == \"SYSLOG\"";

    public SigmaFieldMapping {
        Map<String, String> lowered = new LinkedHashMap<>();
        fields.forEach(
                (sigma, field) -> {
                    EventField.named(field);
                    lowered.put(sigma.toLowerCase(Locale.ROOT), field);
                });
        fields = Map.copyOf(lowered);
        logsources = List.copyOf(logsources);
    }

    public record LogsourceMapping(
            String category, String product, String service, List<String> guards) {

        public LogsourceMapping {
            guards = List.copyOf(guards);
            for (String guard : guards) {
                RuleExpression parsed = RuleExpressionParser.parse(guard);
                if (parsed.isWindowed() || parsed.condition() instanceof Condition.Or) {
                    throw new IllegalArgumentException(
                            "a guard is one predicate, with any 'or' bracketed: " + guard);
                }
            }
        }

        boolean matches(SigmaRule.Logsource logsource) {
            return same(category, logsource.category())
                    && same(product, logsource.product())
                    && same(service, logsource.service());
        }

        private static boolean same(String wanted, String actual) {
            if (wanted == null) {
                return true;
            }
            return wanted.isEmpty() ? actual == null : wanted.equalsIgnoreCase(actual);
        }
    }

    public static SigmaFieldMapping defaults() {
        Map<String, String> fields = new LinkedHashMap<>();

        fields.put("c-ip", "srcIp");
        fields.put("cs-method", "method");
        fields.put("cs-uri", "path");
        fields.put("cs-uri-stem", "uriStem");

        fields.put("cs-uri-query", "path");
        fields.put("cs-version", "protocol");
        fields.put("sc-status", "status");
        fields.put("sc-bytes", "bytes");
        fields.put("cs-user-agent", "userAgent");
        fields.put("cs(user-agent)", "userAgent");
        fields.put("cs-referer", "referrer");
        fields.put("cs-referrer", "referrer");
        fields.put("cs(referer)", "referrer");
        fields.put("cs-username", "user");
        fields.put("s-computername", "host");

        fields.put("source.ip", "srcIp");
        fields.put("client.ip", "srcIp");
        fields.put("source.port", "srcPort");
        fields.put("client.port", "srcPort");
        fields.put("user.name", "user");
        fields.put("http.request.method", "method");
        fields.put("url.original", "path");
        fields.put("url.path", "uriStem");
        fields.put("url.query", "uriQuery");
        fields.put("http.version", "protocol");
        fields.put("http.response.status_code", "status");
        fields.put("http.response.body.bytes", "bytes");
        fields.put("http.response.bytes", "bytes");
        fields.put("user_agent.original", "userAgent");
        fields.put("http.request.referrer", "referrer");
        fields.put("host.name", "host");
        fields.put("hostname", "host");
        fields.put("message", "message");

        List<String> http = List.of(HTTP_REQUEST);
        List<String> syslog = List.of(SYSLOG);
        List<LogsourceMapping> logsources =
                List.of(
                        new LogsourceMapping("webserver", null, null, http),
                        new LogsourceMapping("", "apache", "access", http),
                        new LogsourceMapping("", "nginx", "access", http),
                        new LogsourceMapping("", "linux", "sshd", appName("sshd")),
                        new LogsourceMapping("", "linux", "sudo", appName("sudo")),
                        new LogsourceMapping("", "linux", "auth", syslog),
                        new LogsourceMapping("", "linux", "syslog", syslog),
                        new LogsourceMapping("", "linux", "cron", syslog),
                        new LogsourceMapping("", "linux", "", syslog));
        return new SigmaFieldMapping(fields, logsources);
    }

    String field(String sigmaField) {
        String mapped = fields.get(sigmaField.toLowerCase(Locale.ROOT));
        if (mapped != null) {
            return mapped;
        }
        if (!ATTRIBUTE_KEY.matcher(sigmaField).matches()) {
            throw new SigmaException(
                    "field '" + sigmaField + "' has no mapping and is not a usable attribute key");
        }
        return EventField.ATTRIBUTES_PREFIX + sigmaField;
    }

    List<String> guards(SigmaRule.Logsource logsource) {
        for (LogsourceMapping mapping : logsources) {
            if (mapping.matches(logsource)) {
                return mapping.guards();
            }
        }
        throw new SigmaException("no mapping for log source " + logsource);
    }

    private static List<String> appName(String program) {
        return List.of(SYSLOG, "attributes.appName == \"" + program + "\"");
    }
}
