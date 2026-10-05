package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

/**
 * The built-in path traversal rule: a request that climbs out of the directory it names, or reaches
 * for a file no web server should serve.
 *
 * <p>Most patterns read {@code decodedPath}, the path and query string percent-decoded (up to three
 * times), so {@code %2e%2e%2f}, {@code ..%5c} and {@code %252e%252e%252f} are all {@code ../} or
 * {@code ..\}. A slash is {@code /} or {@code \}, or their fullwidth and division-slash look-alikes
 * that some servers fold into them; a dot is {@code .} or a fullwidth one. The rule ignores case
 * and fires on any of:
 *
 * <ul>
 *   <li>a parent segment followed by a slash, anywhere: {@code ../}, {@code ..\}, the filter dodges
 *       {@code ....//} and {@code ..././}, and {@code /static../} against an off-by-slash alias;
 *   <li>a parent segment ending the path, a segment or a query value: {@code /..}, {@code /..;/}
 *       (Tomcat's path parameter), {@code /..?x}, {@code ?dir=..&};
 *   <li>IIS {@code %u} escapes of a dot or a slash, which the decoder leaves alone: {@code %u002e},
 *       {@code %u2215}, …;
 *   <li>a NUL byte ({@code %00}), which cuts a file name short of the extension a server appends;
 *   <li>Unix files read by traversal: {@code etc/passwd}, {@code etc/shadow}, {@code etc/hosts}, …,
 *       {@code /proc/self/…}, {@code /proc/<pid>/environ}, {@code .ssh/}, {@code .bash_history},
 *       {@code .htpasswd};
 *   <li>Windows ones: {@code boot.ini}, {@code win.ini}, {@code system.ini}, {@code
 *       windows\system32\}.
 * </ul>
 *
 * <p>One pattern reads {@code path} as the server logged it: an overlong UTF-8 sequence such as
 * {@code %c0%ae}, {@code %c0%af} or {@code %e0%80%af}. It is never valid UTF-8 and exists only to
 * slip a dot or a slash past a filter, but the decoder turns it into U+FFFD, so it is looked for
 * before decoding, with any number of {@code 25}s after each {@code %} for double encoding.
 *
 * <p>Browsers resolve dot segments before sending a request, so a {@code ..} that reaches the log
 * was sent on purpose. Every repetition is possessive, so a padded request is matched in linear
 * time.
 *
 * <p>The rule fires once per matching request, with no window: one attempt is already worth an
 * alert, and a scanner's burst is for the alerting side to group.
 *
 * <p>Flyway migration {@code V10__path_traversal_rule.sql} stores this rule in {@code alert_rule}
 * under {@link #NAME}, where it can be tuned or disabled; this class is the reference for that row
 * and for running the rule without a database.
 */
public final class PathTraversalRule {

    /** The rule's name in {@code alert_rule}. */
    public static final String NAME = "path-traversal";

    public static final Severity SEVERITY = Severity.ERROR;

    /** A dot or a fullwidth dot. */
    private static final String DOT = "[.\\x{FF0E}]";

    /**
     * A slash or a backslash, or a fullwidth or division-slash look-alike. The backslash is written
     * {@code \x5c} so neither the rule string nor the migration's SQL literal has to escape it.
     */
    private static final String SLASH = "[/\\x5c\\x{FF0F}\\x{FF3C}\\x{2215}\\x{2216}]";

    /** A percent sign, then any number of {@code 25}s: the same escape encoded once or more. */
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

    /** Overlong two-, three- and four-byte UTF-8 sequences, before decoding. */
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

    /** The rule ready for a {@link RuleEngine}, with no stored row behind it. */
    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
