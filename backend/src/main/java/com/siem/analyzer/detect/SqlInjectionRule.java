package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

public final class SqlInjectionRule {

    public static final String NAME = "sql-injection";

    public static final Severity SEVERITY = Severity.ERROR;

    private static final String GAP = "(?:\\s|/\\*[^*]*+\\*/)*+";

    private static final String GAP1 = "(?:\\s|/\\*[^*]*+\\*/)++";

    private static final String QUOTE = "[\\x22\\x27]";

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

    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
