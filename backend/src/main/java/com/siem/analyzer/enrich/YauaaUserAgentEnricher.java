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

    private static final String HACKER = "Hacker";

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

        if (header.isEmpty() || "-".equals(header)) {
            return Optional.empty();
        }
        UserAgent parsed;
        try {
            parsed = current.parse(header);
        } catch (RuntimeException e) {

            LOG.debugf(e, "User-Agent classification failed");
            return Optional.empty();
        }
        return toEnrichment(parsed);
    }

    private static Optional<UserAgentEnrichment> toEnrichment(UserAgent parsed) {
        String deviceClass = value(parsed, UserAgent.DEVICE_CLASS);
        String agentClass = value(parsed, UserAgent.AGENT_CLASS);
        if (HACKER.equals(deviceClass) || HACKER.equals(agentClass)) {

            return Optional.of(
                    new UserAgentEnrichment(null, null, null, null, HACKER, HACKER, true));
        }
        String browser = value(parsed, UserAgent.AGENT_NAME);
        String browserVersion = value(parsed, UserAgent.AGENT_VERSION);
        String os = value(parsed, UserAgent.OPERATING_SYSTEM_NAME);
        String osVersion = value(parsed, UserAgent.OPERATING_SYSTEM_VERSION);
        if (browser == null && os == null && deviceClass == null && agentClass == null) {

            return Optional.empty();
        }
        boolean bot = isBotClass(deviceClass) || isBotClass(agentClass);
        return Optional.of(
                new UserAgentEnrichment(
                        browser, browserVersion, os, osVersion, deviceClass, agentClass, bot));
    }

    private static boolean isBotClass(String value) {

        return value != null && BOT_CLASSES.contains(value);
    }

    private static String value(UserAgent parsed, String field) {
        AgentField agentField = parsed.get(field);
        if (agentField == null || agentField.isDefaultValue()) {
            return null;
        }
        String value = agentField.getValue();
        return value == null || value.isBlank() ? null : value;
    }
}
