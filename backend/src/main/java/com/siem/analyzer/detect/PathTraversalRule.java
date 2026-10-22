package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

public final class PathTraversalRule {

    public static final String NAME = "path-traversal";

    public static final Severity SEVERITY = Severity.ERROR;

    private static final String DOT = "[.\\x{FF0E}]";

    private static final String SLASH = "[/\\x5c\\x{FF0F}\\x{FF3C}\\x{2215}\\x{2216}]";

    private static final String PERCENT = "%(?:25)*+";

    static final List<String> DECODED_PATTERNS =
            List.of(
                    DOT + "{2}" + SLASH,
                    "(?:^|" + SLASH + "|=)" + DOT + "{2}(?:$|[;?#&])",
                    "%u(?:002e|002f|005c|ff0e|ff0f|ff3c|2215|2216)",
                    "\\x00",
                    "\\betc"
                            + SLASH
                            + "++(?:passwd|shadow|group|gshadow|sudoers|hosts|issue|crontab)\\b",
                    "\\bproc"
                            + SLASH
                            + "++(?:self"
                            + SLASH
                            + "|\\d++"
                            + SLASH
                            + "++(?:environ|cmdline|maps|mem)\\b)",
                    "\\.(?:ssh" + SLASH + "|bash_history\\b|htpasswd\\b)",
                    "\\b(?:boot|win|system)\\.ini\\b",
                    "\\bwindows" + SLASH + "++system32" + SLASH);

    static final String OVERLONG =
            PERCENT
                    + "(?:c[01]|e0"
                    + PERCENT
                    + "[89][0-9a-f]|f0"
                    + PERCENT
                    + "8[0-9a-f]"
                    + PERCENT
                    + "[89ab][0-9a-f])"
                    + PERCENT
                    + "[89ab][0-9a-f]";

    public static final String EXPRESSION =
            "decodedPath matches \"(?i)"
                    + String.join("|", DECODED_PATTERNS)
                    + "\" or path matches \"(?i)"
                    + OVERLONG
                    + "\"";

    private PathTraversalRule() {}

    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
