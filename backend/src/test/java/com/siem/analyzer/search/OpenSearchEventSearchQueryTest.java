package com.siem.analyzer.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Severity;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@QuarkusTest
class OpenSearchEventSearchQueryTest {

    private static final Instant T0 = Instant.parse("2026-09-01T10:00:00Z");

    @Inject OpenSearchEventSearch search;
    @Inject Rest5Client restClient;
    @Inject AppConfig appConfig;
    @Inject SearchIndexInitializer initializer;

    @BeforeEach
    void seed() throws IOException {
        try {
            restClient.performRequest(new Request("DELETE", "/" + appConfig.search().indexName()));
        } catch (Exception ignored) {
        }
        initializer.ensureIndex();

        search.index(
                List.of(
                        event(
                                1L,
                                1L,
                                T0,
                                Severity.ERROR,
                                "failed login for admin",
                                "203.0.113.7 - admin [01/Sep/2026] \"POST /login\" 401",
                                Map.of("srcIp", "203.0.113.7", "host", "web-01", "status", 401)),
                        event(
                                2L,
                                1L,
                                T0.plusSeconds(60),
                                Severity.INFO,
                                "login succeeded",
                                "203.0.113.9 - alice [01/Sep/2026] \"POST /login\" 200",
                                Map.of("srcIp", "203.0.113.9", "host", "web-01", "status", 200)),
                        event(
                                3L,
                                2L,
                                T0.plusSeconds(120),
                                Severity.CRITICAL,
                                "disk failure",
                                "kernel: I/O error on sda1",
                                Map.of("host", "db-01"))));
        restClient.performRequest(
                new Request("POST", "/" + appConfig.search().alias() + "/_refresh"));
    }

    @Test
    void filtersBySeverity() {
        SearchPage page =
                search.search(EventQuery.builder().severities(Set.of(Severity.CRITICAL)).build());

        assertEquals(1, page.hits().size());
        assertEquals(3L, page.hits().get(0).eventId());
        assertEquals(1L, page.totalHits());
    }

    @Test
    void filtersBySource() {
        SearchPage page = search.search(EventQuery.builder().sourceIds(Set.of(2L)).build());

        assertEquals(1, page.hits().size());
        assertEquals(3L, page.hits().get(0).eventId());
    }

    @Test
    void filtersByHalfOpenTimeRange() {
        SearchPage page =
                search.search(EventQuery.builder().from(T0).to(T0.plusSeconds(120)).build());

        assertEquals(2, page.hits().size());
        Set<Long> ids = page.hits().stream().map(EventHit::eventId).collect(Collectors.toSet());
        assertEquals(Set.of(1L, 2L), ids);
    }

    @Test
    void findsASubstringOfTheRawLine() {
        SearchPage page = search.search(EventQuery.builder().substring("203.0.113.").build());

        assertEquals(2, page.hits().size());
        Set<Long> ids = page.hits().stream().map(EventHit::eventId).collect(Collectors.toSet());
        assertEquals(Set.of(1L, 2L), ids);
    }

    @Test
    void findsASubstringThatIsNotAWholeWord() {
        SearchPage page = search.search(EventQuery.builder().substring("sda").build());

        assertEquals(1, page.hits().size());
        assertEquals(3L, page.hits().get(0).eventId());
    }

    @Test
    void ranksFullTextMatchesOnTheMessage() {
        SearchPage page = search.search(EventQuery.builder().fullText("login").build());

        assertEquals(2, page.hits().size());
        Set<Long> ids = page.hits().stream().map(EventHit::eventId).collect(Collectors.toSet());
        assertEquals(Set.of(1L, 2L), ids);
    }

    @Test
    void returnsNewestFirst() {
        SearchPage page = search.search(EventQuery.builder().build());

        assertEquals(List.of(3L, 2L, 1L), page.hits().stream().map(EventHit::eventId).toList());
    }

    @Test
    void pagesWithoutRepeatingOrSkippingAHit() {
        SearchPage first = search.search(EventQuery.builder().size(2).build());
        SearchPage second =
                search.search(EventQuery.builder().size(2).cursor(first.nextCursor()).build());

        assertEquals(List.of(3L, 2L), first.hits().stream().map(EventHit::eventId).toList());
        assertEquals(List.of(1L), second.hits().stream().map(EventHit::eventId).toList());
        assertNull(second.nextCursor());
    }

    @Test
    void countsFacetsAcrossTheWholeMatchNotThePage() {
        SearchPage page = search.search(EventQuery.builder().size(1).withFacets(true).build());

        assertEquals(1, page.hits().size());
        assertEquals(1L, page.facets().bySeverity().get("ERROR"));
        assertEquals(1L, page.facets().bySeverity().get("INFO"));
        assertEquals(1L, page.facets().bySeverity().get("CRITICAL"));
        assertEquals(2L, page.facets().byHost().get("web-01"));
        assertEquals(2, page.facets().bySrcIp().size());
        assertFalse(page.facets().overTime().isEmpty());
    }

    @Test
    void skipsFacetsWhenTheQueryDidNotAskForThem() {
        SearchPage page = search.search(EventQuery.builder().build());

        assertTrue(page.facets().bySeverity().isEmpty());
        assertTrue(page.facets().overTime().isEmpty());
    }

    @Test
    void returnsTheRawLineAndTheStandardFieldsOnAHit() {
        SearchPage page =
                search.search(EventQuery.builder().severities(Set.of(Severity.ERROR)).build());

        EventHit hit = page.hits().get(0);
        assertTrue(hit.raw().contains("POST /login"));
        assertEquals("failed login for admin", hit.message());
        assertEquals(Severity.ERROR, hit.severity());
        assertEquals("web-01", hit.fields().get("host"));
    }

    @Test
    void answersAnImpossibleQueryWithAnEmptyPage() {
        SearchPage page = search.search(EventQuery.builder().substring("zzzz-not-here").build());

        assertTrue(page.hits().isEmpty());
        assertEquals(0L, page.totalHits());
        assertNull(page.nextCursor());
    }

    private IndexableEvent event(
            long id,
            long sourceId,
            Instant at,
            Severity severity,
            String message,
            String raw,
            Map<String, Object> payload) {
        return new IndexableEvent.Builder()
                .eventId(id)
                .sourceId(sourceId)
                .occurredAt(at)
                .ingestedAt(at.plusSeconds(1))
                .severity(severity)
                .message(message)
                .raw(raw)
                .payload(payload)
                .build();
    }
}
