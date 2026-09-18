package com.siem.analyzer.search;

import co.elastic.clients.transport.rest5_client.low_level.Request;
import co.elastic.clients.transport.rest5_client.low_level.Response;
import co.elastic.clients.transport.rest5_client.low_level.ResponseException;
import co.elastic.clients.transport.rest5_client.low_level.Rest5Client;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Severity;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.jboss.logging.Logger;

/**
 * The only class that speaks OpenSearch's wire protocol.
 *
 * <p>Requests are built as Jackson trees and serialised once. Nothing is concatenated into a
 * request body: a query carries caller input, and a body assembled from strings is a body whose
 * escaping is decided by whoever typed the search box.
 */
@ApplicationScoped
public class OpenSearchEventSearch implements EventSearch {

    private static final Logger LOG = Logger.getLogger(OpenSearchEventSearch.class);

    private final Rest5Client restClient;
    private final AppConfig appConfig;
    private final ObjectMapper objectMapper;

    @Inject
    public OpenSearchEventSearch(
            Rest5Client restClient, AppConfig appConfig, ObjectMapper objectMapper) {
        this.restClient = restClient;
        this.appConfig = appConfig;
        this.objectMapper = objectMapper;
    }

    @Override
    public void index(List<IndexableEvent> events) {
        if (events.isEmpty()) {
            return;
        }
        for (int start = 0; start < events.size(); start += appConfig.search().bulkSize()) {
            int end = Math.min(start + appConfig.search().bulkSize(), events.size());
            bulk(events.subList(start, end));
        }
    }

    @Override
    public SearchPage search(EventQuery query) {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("size", query.size());
        body.put("track_total_hits", true);
        body.put("timeout", appConfig.search().queryTimeout().toSeconds() + "s");
        body.set("query", queryClause(query));
        body.set("sort", sortClause(query.order()));
        if (query.cursor() != null) {
            ArrayNode after = body.putArray("search_after");
            after.add(query.cursor().occurredAt().toEpochMilli());
            after.add(query.cursor().eventId());
        }
        if (query.withFacets()) {
            body.set("aggs", aggregations());
        }

        Request request = new Request("POST", "/" + appConfig.search().alias() + "/_search");
        request.setEntity(new StringEntity(body.toString(), ContentType.APPLICATION_JSON));

        try {
            Response response = restClient.performRequest(request);
            if (response.getStatusCode() >= 400) {
                throw new SearchUnavailableException(
                        "Search failed with status: HTTP " + response.getStatusCode());
            }
            return toPage(objectMapper.readTree(response.getEntity().getContent()), query);
        } catch (ResponseException e) {
            throw new SearchUnavailableException("Could not run a search", e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not run a search", e);
        }
    }

    @Override
    public boolean available() {
        try {
            Response response = restClient.performRequest(new Request("GET", "/_cluster/health"));
            return response.getStatusCode() == 200;
        } catch (IOException | RuntimeException e) {
            LOG.debugf(e, "Search engine did not answer a health request");
            return false;
        }
    }

    /**
     * The bool query.
     *
     * <p>Filters go in {@code filter}, which skips scoring and is cacheable. Only the full-text
     * clause goes in {@code must}, because it is the one part whose score orders anything — and
     * even then the sort below is by time, so the score serves relevance debugging rather than
     * ordering.
     */
    private ObjectNode queryClause(EventQuery query) {
        ObjectNode bool = objectMapper.createObjectNode();
        ArrayNode filters = bool.putObject("bool").putArray("filter");
        ArrayNode must = ((ObjectNode) bool.path("bool")).putArray("must");

        if (query.from() != null || query.to() != null) {
            ObjectNode range = objectMapper.createObjectNode();
            ObjectNode bounds = range.putObject("range").putObject("occurred_at");
            if (query.from() != null) {
                bounds.put("gte", query.from().toString());
            }
            if (query.to() != null) {
                // Exclusive, so consecutive windows neither overlap nor leave a gap. Same
                // contract as LogEventRepository.listForSourceBetween.
                bounds.put("lt", query.to().toString());
            }
            filters.add(range);
        }
        if (!query.sourceIds().isEmpty()) {
            ObjectNode terms = objectMapper.createObjectNode();
            ArrayNode values = terms.putObject("terms").putArray("source_id");
            query.sourceIds().forEach(values::add);
            filters.add(terms);
        }
        if (!query.severities().isEmpty()) {
            ObjectNode terms = objectMapper.createObjectNode();
            ArrayNode values = terms.putObject("terms").putArray("severity");
            query.severities().forEach(severity -> values.add(severity.name()));
            filters.add(terms);
        }
        if (!query.srcIps().isEmpty()) {
            // `terms` on an `ip` field takes addresses and CIDR ranges alike.
            ObjectNode terms = objectMapper.createObjectNode();
            ArrayNode values = terms.putObject("terms").putArray("src_ip");
            query.srcIps().forEach(ip -> values.add(ip.value()));
            filters.add(terms);
        }
        if (!query.statuses().isEmpty()) {
            // Any of the ranges. An event without a status matches none of them, so a status
            // filter narrows the result to HTTP events.
            ObjectNode anyStatus = objectMapper.createObjectNode();
            ObjectNode inner = anyStatus.putObject("bool");
            ArrayNode should = inner.putArray("should");
            for (StatusFilter status : query.statuses()) {
                ObjectNode range = should.addObject();
                range.putObject("range")
                        .putObject("status")
                        .put("gte", status.from())
                        .put("lte", status.to());
            }
            inner.put("minimum_should_match", 1);
            filters.add(anyStatus);
        }
        if (query.substring() != null) {
            // A literal substring, not a pattern: the caller's asterisks and question marks
            // are escaped so a search box cannot turn into a scan of the whole index.
            ObjectNode wildcard = objectMapper.createObjectNode();
            wildcard.putObject("wildcard")
                    .putObject("raw")
                    .put("value", "*" + escapeWildcard(query.substring()) + "*")
                    .put("case_insensitive", true);
            filters.add(wildcard);
        }
        if (query.fullText() != null) {
            ObjectNode match = objectMapper.createObjectNode();
            match.putObject("match").put("message", query.fullText());
            must.add(match);
        }
        return bool;
    }

    /**
     * Escapes the two characters {@code wildcard} treats as pattern syntax.
     *
     * <p>Callers search for text, not for patterns. Leaving {@code *} through would let one query
     * ask the engine to verify every document in the index.
     */
    private String escapeWildcard(String literal) {
        return literal.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?");
    }

    /**
     * By event time, with the identifier breaking ties so the sort key is unique.
     *
     * <p>Both keys share one direction: {@code search_after} compares the cursor against them in
     * order, so a mixed direction would page through a different sequence than the one sorted.
     */
    private ArrayNode sortClause(SortOrder order) {
        ArrayNode sort = objectMapper.createArrayNode();
        sort.addObject().putObject("occurred_at").put("order", order.engineValue());
        sort.addObject().putObject("event_id").put("order", order.engineValue());
        return sort;
    }

    /** Facets over the whole match. Every field here is an explicitly mapped one. */
    private ObjectNode aggregations() {
        ObjectNode aggs = objectMapper.createObjectNode();
        aggs.putObject("by_severity").putObject("terms").put("field", "severity").put("size", 10);
        aggs.putObject("by_source").putObject("terms").put("field", "source_id").put("size", 20);
        aggs.putObject("by_host").putObject("terms").put("field", "host").put("size", 20);
        aggs.putObject("by_src_ip").putObject("terms").put("field", "src_ip").put("size", 20);
        aggs.putObject("over_time")
                .putObject("date_histogram")
                .put("field", "occurred_at")
                .put("calendar_interval", "hour")
                .put("min_doc_count", 1);
        return aggs;
    }

    private SearchPage toPage(JsonNode response, EventQuery query) {
        List<EventHit> hits = new ArrayList<>();
        for (JsonNode raw : response.path("hits").path("hits")) {
            hits.add(toHit(raw.path("_source")));
        }
        long total = response.path("hits").path("total").path("value").asLong();
        // A full page may have more behind it; a short one cannot.
        SearchCursor next = hits.size() < query.size() ? null : hits.get(hits.size() - 1).cursor();
        EventFacets facets =
                query.withFacets() ? toFacets(response.path("aggregations")) : EventFacets.none();
        return new SearchPage(hits, total, next, facets);
    }

    private EventHit toHit(JsonNode source) {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (String field :
                List.of(
                        "format",
                        "host",
                        "src_ip",
                        "src_port",
                        "user",
                        "method",
                        "path",
                        "protocol",
                        "status",
                        "bytes",
                        "referrer",
                        "user_agent")) {
            JsonNode value = source.get(field);
            if (value != null && !value.isNull()) {
                // The camelCase name the payload contract uses, so a caller sees one
                // vocabulary rather than the index's snake_case alongside it.
                fields.put(
                        toCamelCase(field),
                        value.isNumber() ? value.numberValue() : value.asText());
            }
        }
        return new EventHit(
                source.path("event_id").asLong(),
                source.path("source_id").asLong(),
                Instant.parse(source.path("occurred_at").asText()),
                Instant.parse(source.path("ingested_at").asText()),
                Severity.valueOf(source.path("severity").asText()),
                source.path("message").asText(),
                source.path("raw").asText(),
                fields);
    }

    private String toCamelCase(String snake) {
        StringBuilder out = new StringBuilder();
        boolean upper = false;
        for (char c : snake.toCharArray()) {
            if (c == '_') {
                upper = true;
                continue;
            }
            out.append(upper ? Character.toUpperCase(c) : c);
            upper = false;
        }
        return out.toString();
    }

    private EventFacets toFacets(JsonNode aggregations) {
        List<EventFacets.TimeBucket> overTime = new ArrayList<>();
        for (JsonNode bucket : aggregations.path("over_time").path("buckets")) {
            overTime.add(
                    new EventFacets.TimeBucket(
                            Instant.ofEpochMilli(bucket.path("key").asLong()),
                            bucket.path("doc_count").asLong()));
        }
        return new EventFacets(
                terms(aggregations.path("by_severity")),
                terms(aggregations.path("by_source")),
                terms(aggregations.path("by_host")),
                terms(aggregations.path("by_src_ip")),
                overTime);
    }

    private Map<String, Long> terms(JsonNode aggregation) {
        Map<String, Long> counts = new LinkedHashMap<>();
        for (JsonNode bucket : aggregation.path("buckets")) {
            counts.put(bucket.path("key").asText(), bucket.path("doc_count").asLong());
        }
        return counts;
    }

    /**
     * Sends one `_bulk` request and fails if any of its items did.
     *
     * <p>A bulk response answers 200 even when individual items were rejected, so the per-item
     * errors are what decides the outcome. A partially applied batch is re-sent whole by the
     * caller: the writes are idempotent, so repeating the ones that worked costs nothing.
     */
    private void bulk(List<IndexableEvent> events) {
        StringBuilder body = new StringBuilder();
        try {
            for (IndexableEvent event : events) {
                ObjectNode action = objectMapper.createObjectNode();
                action.putObject("index").put("_id", Long.toString(event.eventId()));
                body.append(objectMapper.writeValueAsString(action)).append('\n');
                body.append(objectMapper.writeValueAsString(toDocument(event))).append('\n');
            }
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not serialise a batch of events", e);
        }

        Request request = new Request("POST", "/" + appConfig.search().alias() + "/_bulk");
        request.setEntity(new StringEntity(body.toString(), ContentType.APPLICATION_NDJSON));

        try {
            Response response = restClient.performRequest(request);
            if (response.getStatusCode() >= 400) {
                throw new SearchUnavailableException(
                        "The index refused the bulk request: HTTP " + response.getStatusCode());
            }
            var parsed = objectMapper.readTree(response.getEntity().getContent());
            if (parsed.path("errors").asBoolean()) {
                var firstError = parsed.path("items").findValue("error");
                throw new SearchUnavailableException(
                        "The index refused part of a batch: " + firstError);
            }
        } catch (ResponseException e) {
            throw new SearchUnavailableException("Could not write a batch to the index", e);
        } catch (IOException e) {
            throw new SearchUnavailableException("Could not write a batch to the index", e);
        }
    }

    /** Builds the document for one event, in the field names the mapping declares. */
    private ObjectNode toDocument(IndexableEvent event) {
        ObjectNode document = objectMapper.createObjectNode();
        document.put("event_id", event.eventId());
        document.put("source_id", event.sourceId());
        putText(document, "external_id", event.externalId());
        document.put("occurred_at", event.occurredAt().toString());
        document.put("ingested_at", event.ingestedAt().toString());
        document.put("severity", event.severity().name());
        putText(document, "format", event.format());
        putText(document, "host", event.host());
        putText(document, "src_ip", event.srcIp());
        putNumber(document, "src_port", event.srcPort());
        putText(document, "user", event.user());
        putText(document, "method", event.method());
        putText(document, "path", event.path());
        putText(document, "protocol", event.protocol());
        putNumber(document, "status", event.status());
        putNumber(document, "bytes", event.bytes());
        putText(document, "referrer", event.referrer());
        putText(document, "user_agent", event.userAgent());
        document.put("message", event.message());
        document.put("raw", event.raw());
        if (!event.attributes().isEmpty()) {
            // flat_object holds the whole map as one field, so an unexpected key here grows
            // nothing — which is why `dynamic: strict` above it is safe.
            document.set("attributes", objectMapper.valueToTree(event.attributes()));
        }
        return document;
    }

    private void putText(ObjectNode document, String field, String value) {
        if (value != null) {
            document.put(field, value);
        }
    }

    private void putNumber(ObjectNode document, String field, Number value) {
        if (value != null) {
            document.put(field, value.longValue());
        }
    }
}
