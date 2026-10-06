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

/**
 * How Sigma's vocabulary maps onto this engine's: which {@link EventField} a Sigma field name
 * reads, and which log sources a rule may target.
 *
 * <p><b>Fields.</b> A Sigma field is looked up, ignoring case, in the field table. One that is not
 * there is read from {@code attributes.<name>}, as the source wrote it, which is where the JSON and
 * syslog parsers keep what has no standard slot. A name the rule language cannot spell, such as
 * {@code cs(Cookie)}, is refused rather than guessed at.
 *
 * <p><b>Log sources.</b> The engine sees every event, whatever it came from, so a Sigma rule's
 * {@code logsource} becomes a guard condition ANDed in front of the rule. Without it a rule such as
 * {@code not sc-status: 200} would fire on every syslog line, which has no status at all. A rule
 * whose log source matches no entry is refused: this platform ingests access logs, syslog and JSON,
 * and a Windows process-creation rule has nothing here to run against.
 *
 * <p>The {@link #defaults() defaults} cover the Sigma {@code webserver} taxonomy (W3C extended log
 * names such as {@code cs-uri-query}), the ECS names a JSON log is likely to use, and Linux syslog.
 *
 * @param fields Sigma field name, lower-cased, to the name of the {@link EventField} it reads
 * @param logsources tried in order; the first that matches a rule's {@code logsource} supplies its
 *     guards
 */
public record SigmaFieldMapping(Map<String, String> fields, List<LogsourceMapping> logsources) {

    /** What the rule language accepts after {@code attributes.} without quoting. */
    private static final Pattern ATTRIBUTE_KEY = Pattern.compile("[\\p{L}_][\\p{L}\\p{Nd}_.\\-]*+");

    /** Guard for HTTP access events, from whichever parser read them. */
    static final String HTTP_REQUEST = "method exists";

    /** Guard for syslog lines. */
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

    /**
     * A log source this engine can serve, and the condition that narrows events to it.
     *
     * <p>Each of {@code category}, {@code product} and {@code service} is {@code null} to match
     * anything, an absent value included; empty to match only a rule that leaves it out; or a value
     * the rule's must equal, ignoring case.
     *
     * @param guards rule-language predicates ANDed in front of the rule, each a single predicate
     *     (bracket an {@code or}); empty for none
     */
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

    /** The mapping the importer uses unless told otherwise. */
    public static SigmaFieldMapping defaults() {
        Map<String, String> fields = new LinkedHashMap<>();
        // Sigma webserver taxonomy: W3C extended log format names.
        fields.put("c-ip", "srcIp");
        fields.put("cs-method", "method");
        fields.put("cs-uri", "path");
        fields.put("cs-uri-stem", "uriStem");
        // The taxonomy means the query string, but SigmaHQ's web rules use it for the whole
        // request target ('cs-uri-query|endswith: /mgmt/tm/util/bash'), so it reads path.
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
        // Elastic Common Schema, as JSON logs often name things.
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
                        // product: linux alone is the keyword-only "any Linux log" rules; a
                        // category such as process_creation needs audit data syslog lacks.
                        new LogsourceMapping("", "linux", "", syslog));
        return new SigmaFieldMapping(fields, logsources);
    }

    /**
     * The rule-language field a Sigma field reads.
     *
     * @throws SigmaException the field is not in the table and cannot be an attribute key
     */
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

    /**
     * The guards for a rule's log source; empty when the matching entry needs none.
     *
     * @throws SigmaException no entry matches
     */
    List<String> guards(SigmaRule.Logsource logsource) {
        for (LogsourceMapping mapping : logsources) {
            if (mapping.matches(logsource)) {
                return mapping.guards();
            }
        }
        throw new SigmaException("no mapping for log source " + logsource);
    }

    /** Syslog lines from one program, by the tag syslog gives it. */
    private static List<String> appName(String program) {
        return List.of(SYSLOG, "attributes.appName == \"" + program + "\"");
    }
}
