package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

/**
 * The built-in SQL injection rule: a request whose target carries a SQL injection pattern.
 *
 * <p>The rule reads {@code decodedPath}, the path and query string percent-decoded (twice-encoded
 * too), so {@code %27%20OR%201%3D1} and {@code '+OR+1=1} are both {@code ' OR 1=1}. Between SQL
 * words it accepts whitespace or an inline comment ({@code UNION/**}{@code /SELECT}), and it
 * ignores case. It fires on any of:
 *
 * <ul>
 *   <li>{@code UNION [ALL|DISTINCT] SELECT}, also {@code UNION(SELECT};
 *   <li>a quote closed into a tautology: {@code ' OR 1=1}, {@code ' or 'a'='a}, {@code " OR ""="},
 *       {@code ') AND 1=1}, {@code ' || 'x' LIKE 'x};
 *   <li>an unquoted numeric one: {@code 1 OR 1=1}, {@code 5 AND 1=2};
 *   <li>a quote followed by a comment that cuts off the rest of the query: {@code admin'--}, {@code
 *       admin'#}, {@code '/*};
 *   <li>column counting after a quote: {@code ' ORDER BY 3}, {@code ' GROUP BY 1};
 *   <li>a stacked statement: {@code ; DROP TABLE}, {@code ; EXEC xp_…}, {@code ; INSERT INTO}, …;
 *   <li>time-based blind probes: {@code SLEEP(5)}, {@code pg_sleep(5)}, {@code BENCHMARK(…)},
 *       {@code WAITFOR DELAY '0:0:5'};
 *   <li>a subquery after a boolean: {@code AND (SELECT …}, and the error- and file-based functions
 *       {@code EXTRACTVALUE(}, {@code UPDATEXML(}, {@code LOAD_FILE(}, {@code INTO OUTFILE};
 *   <li>catalogue and system names no ordinary URL carries: {@code @@version}, {@code
 *       information_schema}, {@code sqlite_master}, {@code sysobjects}, {@code xp_cmdshell}.
 * </ul>
 *
 * <p>Every gap is matched possessively, so a request padded with thousands of spaces or comments
 * costs linear time: the client chooses the input, and the regex runs on every event.
 *
 * <p>The rule fires once per matching request, with no window: one attempt is already worth an
 * alert, and a scanner's burst is for the alerting side to group.
 *
 * <p>Flyway migration {@code V9__sql_injection_rule.sql} stores this rule in {@code alert_rule}
 * under {@link #NAME}, where it can be tuned or disabled; this class is the reference for that row
 * and for running the rule without a database.
 */
public final class SqlInjectionRule {

    /** The rule's name in {@code alert_rule}. */
    public static final String NAME = "sql-injection";

    public static final Severity SEVERITY = Severity.ERROR;

    /** Whitespace or an inline comment, any number of them. */
    private static final String GAP = "(?:\\s|/\\*[^*]*+\\*/)*+";

    /** Whitespace or an inline comment, at least one. */
    private static final String GAP1 = "(?:\\s|/\\*[^*]*+\\*/)++";

    /**
     * A single or double quote, as hex escapes so the pattern needs no quoting inside the rule
     * string or the migration's SQL literal.
     */
    private static final String QUOTE = "[\\x22\\x27]";

    /**
     * A quote, optionally followed by a closing parenthesis, as when breaking out of {@code IN
     * (…)}.
     */
    private static final String CLOSE = QUOTE + GAP + "\\)?" + GAP;

    static final List<String> PATTERNS =
            List.of(
                    "\\bunion(?:"
                            + GAP1
                            + "(?:all|distinct))?(?:"
                            + GAP1
                            + "|"
                            + GAP
                            + "\\("
                            + GAP
                            + ")select\\b",
                    CLOSE
                            + "(?:(?:or|and)\\b|\\|\\||&&)"
                            + GAP
                            + "\\(?"
                            + GAP
                            + QUOTE
                            + "?\\w*+"
                            + QUOTE
                            + "?"
                            + GAP
                            + "(?:=|<>|!=|\\blike\\b)"
                            + GAP
                            + "[\\x22\\x27\\w(]",
                    "\\b(?:or|and)" + GAP1 + "\\d++" + GAP + "(?:=|<>|!=)" + GAP + "\\d++\\b",
                    CLOSE + "(?:--|/\\*|#(?=$|[\\s&]))",
                    CLOSE + "(?:order|group)" + GAP1 + "by\\b",
                    ";"
                            + GAP
                            + "(?:drop|truncate|alter|create|delete|insert|update|exec(?:ute)?"
                            + "|declare)"
                            + GAP1
                            + "\\w",
                    "\\b(?:sleep|pg_sleep|benchmark)" + GAP + "\\(" + GAP + "\\d",
                    "\\bwaitfor" + GAP1 + "delay" + GAP1 + QUOTE,
                    "\\b(?:and|or)" + GAP + "\\(" + GAP + "select\\b",
                    "\\b(?:extractvalue|updatexml|load_file)" + GAP + "\\(",
                    "\\binto" + GAP1 + "(?:out|dump)file\\b",
                    "\\b(?:information_schema|sqlite_master|sysobjects|xp_cmdshell)\\b",
                    "@@version\\b");

    public static final String EXPRESSION =
            "decodedPath matches \"(?i)" + String.join("|", PATTERNS) + "\"";

    private SqlInjectionRule() {}

    /** The rule ready for a {@link RuleEngine}, with no stored row behind it. */
    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
