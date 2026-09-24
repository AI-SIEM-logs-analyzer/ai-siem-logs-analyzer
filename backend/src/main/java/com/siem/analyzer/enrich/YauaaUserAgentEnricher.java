package com.siem.analyzer.enrich;

import com.siem.analyzer.config.AppConfig;
import io.quarkus.runtime.Startup;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import nl.basjes.parse.useragent.AgentField;
import nl.basjes.parse.useragent.UserAgent;
import nl.basjes.parse.useragent.UserAgentAnalyzer;
import org.jboss.logging.Logger;

/**
 * Classifies User-Agent headers with Yauaa.
 *
 * <p>The analyzer is built once, at start-up ({@link Startup}), because building it compiles
 * Yauaa's whole rule set and takes seconds: paid lazily, that cost would land on whichever upload
 * happened to be first. It is restricted to the fields this class reads, which is what keeps both
 * that build and every parse cheap: Yauaa skips every rule that only feeds a field nobody asked
 * for.
 *
 * <p>{@link UserAgentAnalyzer#parse(String)} is thread-safe, so one analyzer serves every consumer
 * thread.
 */
@Startup
@ApplicationScoped
public class YauaaUserAgentEnricher implements UserAgentEnricher {

    private static final Logger LOG = Logger.getLogger(YauaaUserAgentEnricher.class);

    private static final List<String> FIELDS =
            List.of(
                    UserAgent.AGENT_NAME,
                    UserAgent.AGENT_VERSION,
                    UserAgent.OPERATING_SYSTEM_NAME,
                    UserAgent.OPERATING_SYSTEM_VERSION,
                    UserAgent.DEVICE_CLASS,
                    UserAgent.AGENT_CLASS);

    /**
     * The class Yauaa gives a header carrying an attack (SQL injection, a scanner's signature such
     * as sqlmap or Nmap) or one no real client would send. Yauaa then writes it into every field,
     * agent and operating system names included.
     */
    private static final String HACKER = "Hacker";

    /**
     * Device and agent classes that mean an automated client. Yauaa files command-line tools and
     * HTTP libraries (curl, wget, python-requests) and headless browsers as {@code Robot} too,
     * which is what a SIEM wants from a bot flag. {@code Robot Imitator} claims to be a well-known
     * crawler without being one; {@code Hacker} is never a person at a browser.
     */
    private static final Set<String> BOT_CLASSES =
            Set.of("Robot", "Robot Mobile", "Robot Imitator", "Cloud Application", HACKER);

    private final boolean enabled;
    private final int cacheSize;

    private volatile UserAgentAnalyzer analyzer;

    @Inject
    public YauaaUserAgentEnricher(AppConfig config) {
        this(config.userAgent().enabled(), config.userAgent().cacheSize());
    }

    YauaaUserAgentEnricher(boolean enabled, int cacheSize) {
        this.enabled = enabled;
        this.cacheSize = cacheSize;
    }

    @PostConstruct
    void open() {
        if (!enabled) {
            LOG.info("User-Agent classification is disabled; events will carry no ua fields");
            return;
        }
        long started = System.nanoTime();
        UserAgentAnalyzer.UserAgentAnalyzerBuilder builder =
                UserAgentAnalyzer.newBuilder()
                        .withFields(FIELDS)
                        .hideMatcherLoadStats()
                        // The rule files carry thousands of test cases of their own; nothing here
                        // runs them, so there is no reason to keep them in the heap.
                        .dropTests()
                        .immediateInitialization();
        analyzer =
                cacheSize > 0
                        ? builder.withCache(cacheSize).build()
                        : builder.withoutCache().build();
        LOG.infof(
                "User-Agent classification active (built in %d ms)",
                (System.nanoTime() - started) / 1_000_000);
    }

    @PreDestroy
    void close() {
        UserAgentAnalyzer current = analyzer;
        analyzer = null;
        if (current != null) {
            current.destroy();
        }
    }

    @Override
    public Optional<UserAgentEnrichment> classify(String userAgent) {
        UserAgentAnalyzer current = analyzer;
        if (current == null || userAgent == null) {
            return Optional.empty();
        }
        String header = userAgent.trim();
        // "-" is how access logs spell "the client sent no User-Agent", not a header to classify.
        if (header.isEmpty() || "-".equals(header)) {
            return Optional.empty();
        }
        UserAgent parsed;
        try {
            parsed = current.parse(header);
        } catch (RuntimeException e) {
            // Classification is additive: a header that trips the rule engine costs the event its
            // ua fields, never its place in the ingestion batch.
            LOG.debugf(e, "User-Agent classification failed");
            return Optional.empty();
        }
        return toEnrichment(parsed);
    }

    private static Optional<UserAgentEnrichment> toEnrichment(UserAgent parsed) {
        String deviceClass = value(parsed, UserAgent.DEVICE_CLASS);
        String agentClass = value(parsed, UserAgent.AGENT_CLASS);
        if (HACKER.equals(deviceClass) || HACKER.equals(agentClass)) {
            // "Hacker" as a browser or an operating system name would sit in those facets beside
            // Chrome and Windows; the class fields already say it, so only they carry it.
            return Optional.of(
                    new UserAgentEnrichment(null, null, null, null, HACKER, HACKER, true));
        }
        String browser = value(parsed, UserAgent.AGENT_NAME);
        String browserVersion = value(parsed, UserAgent.AGENT_VERSION);
        String os = value(parsed, UserAgent.OPERATING_SYSTEM_NAME);
        String osVersion = value(parsed, UserAgent.OPERATING_SYSTEM_VERSION);
        if (browser == null && os == null && deviceClass == null && agentClass == null) {
            // Nothing recognised at all: writing uaBot=false for it would claim a finding the
            // header does not support.
            return Optional.empty();
        }
        boolean bot = isBotClass(deviceClass) || isBotClass(agentClass);
        return Optional.of(
                new UserAgentEnrichment(
                        browser, browserVersion, os, osVersion, deviceClass, agentClass, bot));
    }

    private static boolean isBotClass(String value) {
        // Set.of(...).contains(null) throws rather than answering false.
        return value != null && BOT_CLASSES.contains(value);
    }

    /**
     * The field's value, or {@code null} when Yauaa fell back to its default ({@code Unknown},
     * {@code ??}): a default is Yauaa saying it does not know, not a value to index.
     */
    private static String value(UserAgent parsed, String field) {
        AgentField agentField = parsed.get(field);
        if (agentField == null || agentField.isDefaultValue()) {
            return null;
        }
        String value = agentField.getValue();
        return value == null || value.isBlank() ? null : value;
    }
}
