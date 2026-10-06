package com.siem.analyzer.detect;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.NormalizedEvent;
import java.time.Instant;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The fields {@link EventField} derives rather than reads. */
class EventFieldTest {

    private static NormalizedEvent requestFor(String path) {
        return NormalizedEvent.builder(Instant.EPOCH, LogFormat.ACCESS_LOG, "raw line")
                .path(path)
                .build();
    }

    @ParameterizedTest
    @CsvSource(
            nullValues = "null",
            value = {
                "/index.html, /index.html, null",
                "/search?q=a?b, /search, q=a?b",
                "/search?, /search, null",
                "?q=1, null, q=1",
                "null, null, null",
            })
    void splitsThePathAtTheFirstQuestionMark(String path, String stem, String query) {
        NormalizedEvent event = requestFor(path);

        assertEquals(stem, EventField.named("uriStem").read(event));
        assertEquals(query, EventField.named("uriQuery").read(event));
    }

    @ParameterizedTest
    @CsvSource({"raw", "RAW"})
    void readsTheLineAsReceived(String name) {
        assertEquals("raw line", EventField.named(name).read(requestFor("/")));
    }
}
