package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

/**
 * The built-in scanner User-Agent rule: a request whose User-Agent names an attack tool, carries an
 * attack payload, or is a command-line client that the server turned away.
 *
 * <p>The rule reads {@code userAgent}, ignores case and fires on any of:
 *
 * <ul>
 *   <li>a scanner, fuzzer or attack tool that announces itself: {@code sqlmap}, {@code Nikto},
 *       {@code Nmap Scripting Engine}, {@code masscan}, {@code zgrab}, {@code Nuclei}, {@code
 *       WPScan}, {@code gobuster}, {@code DirBuster}, {@code Fuzz Faster U Fool}, {@code wfuzz},
 *       {@code Acunetix}, {@code Netsparker}, {@code Nessus}, {@code OpenVAS}, {@code w3af}, {@code
 *       Hydra}, {@code ZmEu}, …. One such request is enough;
 *   <li>a payload aimed at whatever logs or parses the header: Shellshock ({@code () {}), Log4Shell
 *       ({@code ${jndi:}, {@code ${${::-j}…}), {@code <script}, {@code UNION SELECT}, {@code
 *       SLEEP(5)}, {@code ../}. No real client sends any of these;
 *   <li>a command-line client or bare HTTP library ({@code curl}, {@code Wget}, {@code
 *       python-requests}, {@code Go-http-client}, {@code libwww-perl}, {@code PowerShell}, …)
 *       whose request was answered 4xx or 5xx. Health checks and scripts use these all day and get
 *       their 2xx, so the client alone is not worth an alert; the same client probing paths it is
 *       refused is how a hand-driven scan looks.
 * </ul>
 *
 * <p>A tool told to borrow a browser's header ({@code sqlmap --random-agent}) passes unseen here;
 * catching it is the job of the rules that look at what it requests.
 *
 * <p>Tool names are matched as whole words, so one inside a longer word ({@code Hydrangea}, {@code
 * nmapper}) does not fire. Every repetition is possessive, so a padded header is matched in linear
 * time.
 *
 * <p>The rule fires once per matching request, with no window: one attempt is already worth an
 * alert, and a scanner's burst is for the alerting side to group.
 *
 * <p>Flyway migration {@code V11__scanner_user_agent_rule.sql} stores this rule in {@code
 * alert_rule} under {@link #NAME}, where it can be tuned or disabled; this class is the reference
 * for that row and for running the rule without a database.
 */
public final class ScannerUserAgentRule {

    /** The rule's name in {@code alert_rule}. */
    public static final String NAME = "scanner-user-agent";

    public static final Severity SEVERITY = Severity.WARNING;

    /** Scanners, fuzzers and attack tools, by the name their default header carries. */
    static final List<String> TOOLS =
            List.of(
                    "sqlmap",
                    "nikto",
                    "nmap",
                    "masscan",
                    "zgrab",
                    "zmap",
                    "nuclei",
                    "wpscan",
                    "joomscan",
                    "droopescan",
                    "dirbuster",
                    "dirb",
                    "gobuster",
                    "feroxbuster",
                    "ffuf",
                    "fuzz faster u fool",
                    "wfuzz",
                    "acunetix",
                    "netsparker",
                    "nessus",
                    "openvas",
                    "w3af",
                    "arachni",
                    "skipfish",
                    "whatweb",
                    "havij",
                    "commix",
                    "fimap",
                    "xsser",
                    "jaeles",
                    "hydra",
                    "zmeu",
                    "morfeus");

    /** Attack payloads aimed at whatever logs or parses the header. */
    static final List<String> PAYLOADS =
            List.of(
                    "\\(\\s*+\\)\\s*+\\{",
                    "\\$\\{(?:jndi|[$:]|(?:lower|upper|env|sys|date|base64|main|ctx)\\b)",
                    "<script\\b",
                    "\\bunion\\s++(?:all\\s++)?select\\b",
                    "\\b(?:sleep|pg_sleep|benchmark)\\s*+\\(\\s*+\\d",
                    "\\.\\./");

    /** Command-line clients and bare HTTP libraries. */
    static final List<String> CLIENTS =
            List.of(
                    "curl",
                    "wget",
                    "python-requests",
                    "python-urllib",
                    "python-httpx",
                    "aiohttp",
                    "go-http-client",
                    "libwww-perl",
                    "lwp-trivial",
                    "windowspowershell",
                    "httpie",
                    "java/\\d");

    public static final String EXPRESSION =
            "userAgent matches \"(?i)\\b(?:"
                    + String.join("|", TOOLS)
                    + ")\\b\" or userAgent matches \"(?i)"
                    + String.join("|", PAYLOADS)
                    + "\" or userAgent matches \"(?i)\\b(?:"
                    + String.join("|", CLIENTS)
                    + ")\" and status >= 400";

    private ScannerUserAgentRule() {}

    /** The rule ready for a {@link RuleEngine}, with no stored row behind it. */
    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
