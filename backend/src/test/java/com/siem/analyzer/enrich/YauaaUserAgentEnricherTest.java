package com.siem.analyzer.enrich;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Optional;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Runs the real Yauaa rule set. Building it takes seconds, so the whole class shares one enricher.
 */
class YauaaUserAgentEnricherTest {

    private static final String CHROME_WINDOWS =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                    + " Chrome/120.0.0.0 Safari/537.36";
    private static final String SAFARI_IPHONE =
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML,"
                    + " like Gecko) Version/17.2 Mobile/15E148 Safari/604.1";
    private static final String GOOGLEBOT =
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)";
    private static final String HEADLESS_CHROME =
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)"
                    + " HeadlessChrome/120.0.0.0 Safari/537.36";

    private static YauaaUserAgentEnricher enricher;

    @BeforeAll
    static void build() {
        enricher = new YauaaUserAgentEnricher(true, 100);
        enricher.open();
    }

    @AfterAll
    static void destroy() {
        enricher.close();
    }

    @Test
    void aDesktopBrowserIsNamedAndIsNotABot() {
        UserAgentEnrichment ua = classify(CHROME_WINDOWS);

        assertEquals("Chrome", ua.browser());
        assertEquals("Windows NT", ua.os());
        assertEquals("Desktop", ua.deviceClass());
        assertEquals("Browser", ua.agentClass());
        assertFalse(ua.bot());
    }

    @Test
    void aPhoneBrowserCarriesItsOperatingSystemVersion() {
        UserAgentEnrichment ua = classify(SAFARI_IPHONE);

        assertEquals("Safari", ua.browser());
        assertEquals("17.2", ua.browserVersion());
        assertEquals("iOS", ua.os());
        assertEquals("17.2", ua.osVersion());
        assertEquals("Phone", ua.deviceClass());
        assertFalse(ua.bot());
    }

    @Test
    void aValueYauaaDoesNotKnowIsLeftOutRatherThanWrittenAsAPlaceholder() {
        // A reduced Chrome header no longer says which Windows release it runs on; Yauaa answers
        // "??", which must not reach the index as though it were a version.
        assertNull(classify(CHROME_WINDOWS).osVersion());
    }

    @Test
    void aCrawlerIsABot() {
        UserAgentEnrichment ua = classify(GOOGLEBOT);

        assertEquals("Googlebot", ua.browser());
        assertEquals("Robot", ua.deviceClass());
        assertTrue(ua.bot());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "curl/8.4.0",
                "Wget/1.21.4",
                "python-requests/2.31.0",
                "Go-http-client/1.1",
                HEADLESS_CHROME
            })
    void toolsLibrariesAndHeadlessBrowsersAreBots(String header) {
        assertTrue(classify(header).bot(), header);
    }

    @ParameterizedTest
    @ValueSource(strings = {"sqlmap/1.7.2#stable (https://sqlmap.org)", "' OR 1=1 --"})
    void anAttackInTheHeaderIsAHackerBotWithNoBrowserOrOperatingSystem(String header) {
        UserAgentEnrichment ua = classify(header);

        assertEquals("Hacker", ua.deviceClass());
        assertEquals("Hacker", ua.agentClass());
        assertTrue(ua.bot());
        assertNull(ua.browser());
        assertNull(ua.browserVersion());
        assertNull(ua.os());
        assertNull(ua.osVersion());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "-", " - "})
    void anAbsentHeaderIsNotClassified(String header) {
        // Yauaa itself would call "-" and "" a Hacker; for an access log they only mean the
        // client sent no header at all.
        assertTrue(enricher.classify(header).isEmpty());
    }

    @Test
    void aDisabledEnricherClassifiesNothing() {
        YauaaUserAgentEnricher disabled = new YauaaUserAgentEnricher(false, 100);
        disabled.open();

        assertTrue(disabled.classify(CHROME_WINDOWS).isEmpty());
    }

    @Test
    void anUncachedEnricherClassifiesTheSameAndNothingOnceClosed() {
        YauaaUserAgentEnricher uncached = new YauaaUserAgentEnricher(true, 0);
        uncached.open();
        try {
            assertEquals(classify(GOOGLEBOT), uncached.classify(GOOGLEBOT).orElseThrow());
        } finally {
            uncached.close();
        }

        assertTrue(uncached.classify(GOOGLEBOT).isEmpty());
    }

    private static UserAgentEnrichment classify(String header) {
        Optional<UserAgentEnrichment> result = enricher.classify(header);
        assertTrue(result.isPresent(), header);
        return result.get();
    }
}
