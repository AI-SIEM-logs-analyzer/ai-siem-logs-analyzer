package com.siem.analyzer.detect;

import com.siem.analyzer.domain.Severity;
import java.util.List;

public final class ScannerUserAgentRule {

    public static final String NAME = "scanner-user-agent";

    public static final Severity SEVERITY = Severity.WARNING;

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

    static final List<String> PAYLOADS =
            List.of(
                    "\\(\\s*+\\)\\s*+\\{",
                    "\\$\\{(?:jndi|[$:]|(?:lower|upper|env|sys|date|base64|main|ctx)\\b)",
                    "<script\\b",
                    "\\bunion\\s++(?:all\\s++)?select\\b",
                    "\\b(?:sleep|pg_sleep|benchmark)\\s*+\\(\\s*+\\d",
                    "\\.\\./");

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

    public static DetectionRule rule() {
        return DetectionRule.of(NAME, SEVERITY, EXPRESSION);
    }
}
