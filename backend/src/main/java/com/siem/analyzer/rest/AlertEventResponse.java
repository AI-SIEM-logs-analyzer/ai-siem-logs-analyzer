package com.siem.analyzer.rest;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.Severity;
import com.siem.analyzer.search.IndexableEvent;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * The event that raised an alert, read from PostgreSQL rather than the search index, so it is there
 * even before the index has caught up.
 *
 * @param fields the parsed fields under the camelCase names a search hit carries, absent ones left
 *     out; whatever the parser could not place is nested under {@code attributes}
 */
public record AlertEventResponse(
        long eventId,
        long sourceId,
        String sourceName,
        Instant occurredAt,
        Instant ingestedAt,
        Severity severity,
        String message,
        String raw,
        Map<String, Object> fields) {

    public static AlertEventResponse from(LogEvent event) {
        IndexableEvent projected = IndexableEvent.from(event);
        Map<String, Object> fields = new LinkedHashMap<>();
        put(fields, "format", projected.format());
        put(fields, "host", projected.host());
        put(fields, "srcIp", projected.srcIp());
        put(fields, "srcPort", projected.srcPort());
        put(fields, "user", projected.user());
        put(fields, "method", projected.method());
        put(fields, "path", projected.path());
        put(fields, "protocol", projected.protocol());
        put(fields, "status", projected.status());
        put(fields, "bytes", projected.bytes());
        put(fields, "referrer", projected.referrer());
        put(fields, "userAgent", projected.userAgent());
        put(fields, "geoCountryIso", projected.geoCountryIso());
        put(fields, "geoCountryName", projected.geoCountryName());
        put(fields, "geoCity", projected.geoCity());
        put(fields, "geoLatitude", projected.geoLatitude());
        put(fields, "geoLongitude", projected.geoLongitude());
        put(fields, "geoAsn", projected.geoAsn());
        put(fields, "geoAsOrg", projected.geoAsOrg());
        put(fields, "uaBrowser", projected.uaBrowser());
        put(fields, "uaBrowserVersion", projected.uaBrowserVersion());
        put(fields, "uaOs", projected.uaOs());
        put(fields, "uaOsVersion", projected.uaOsVersion());
        put(fields, "uaDeviceClass", projected.uaDeviceClass());
        put(fields, "uaAgentClass", projected.uaAgentClass());
        put(fields, "uaBot", projected.uaBot());
        if (!projected.attributes().isEmpty()) {
            fields.put("attributes", projected.attributes());
        }
        return new AlertEventResponse(
                projected.eventId(),
                projected.sourceId(),
                event.getSource().getName(),
                projected.occurredAt(),
                projected.ingestedAt(),
                projected.severity(),
                projected.message(),
                projected.raw(),
                fields);
    }

    private static void put(Map<String, Object> fields, String name, Object value) {
        if (value != null) {
            fields.put(name, value);
        }
    }
}
