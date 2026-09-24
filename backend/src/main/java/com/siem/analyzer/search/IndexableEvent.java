package com.siem.analyzer.search;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One {@link LogEvent} in the shape the index stores.
 *
 * <p>The standard fields are read out of the event's {@code payload}, whose keys are the component
 * names of {@link com.siem.analyzer.domain.NormalizedEvent} — that is the contract every file
 * parser writes to. Anything the parser could not place stays nested under {@code attributes} and
 * reaches the index as a {@code flat_object}: searchable, but deliberately not aggregatable, which
 * is why every field the dashboard facets on appears explicitly here.
 *
 * <p>A payload value of the wrong type is dropped rather than raised. The payload is parser output,
 * the index is derived, and refusing to index an otherwise good event because one field is
 * malformed would hide the event instead of the field.
 *
 * <p>The {@code geo*} fields are the GeoIP enrichment written for the event's source address.
 * {@code geoLocation} is only accepted, and split into {@code geoLatitude}/{@code geoLongitude},
 * when it is a map holding numeric {@code lat} and {@code lon}; anything else leaves both null.
 */
public record IndexableEvent(
        long eventId,
        long sourceId,
        String externalId,
        Instant occurredAt,
        Instant ingestedAt,
        Severity severity,
        String message,
        String raw,
        String format,
        String host,
        String srcIp,
        Integer srcPort,
        String user,
        String method,
        String path,
        String protocol,
        Integer status,
        Long bytes,
        String referrer,
        String userAgent,
        String geoCountryIso,
        String geoCountryName,
        String geoCity,
        Double geoLatitude,
        Double geoLongitude,
        Long geoAsn,
        String geoAsOrg,
        Map<String, Object> attributes) {

    public IndexableEvent {
        attributes =
                attributes == null
                        ? Map.of()
                        : Collections.unmodifiableMap(new LinkedHashMap<>(attributes));
    }

    /** Projects a persisted event, reading its standard fields out of the payload. */
    public static IndexableEvent from(LogEvent event) {
        return new Builder()
                .eventId(event.getId())
                .sourceId(event.getSource().getId())
                .externalId(event.getExternalId())
                .occurredAt(event.getOccurredAt())
                .ingestedAt(event.getIngestedAt())
                .severity(event.getSeverity())
                .message(event.getMessage())
                .raw(event.getRaw())
                .payload(event.getPayload())
                .build();
    }

    /** Assembles an event from its columns plus its payload map. */
    public static final class Builder {

        private long eventId;
        private long sourceId;
        private String externalId;
        private Instant occurredAt;
        private Instant ingestedAt;
        private Severity severity;
        private String message;
        private String raw;
        private Map<String, Object> payload = Map.of();

        public Builder eventId(long value) {
            this.eventId = value;
            return this;
        }

        public Builder sourceId(long value) {
            this.sourceId = value;
            return this;
        }

        public Builder externalId(String value) {
            this.externalId = value;
            return this;
        }

        public Builder occurredAt(Instant value) {
            this.occurredAt = value;
            return this;
        }

        public Builder ingestedAt(Instant value) {
            this.ingestedAt = value;
            return this;
        }

        public Builder severity(Severity value) {
            this.severity = value;
            return this;
        }

        public Builder message(String value) {
            this.message = value;
            return this;
        }

        public Builder raw(String value) {
            this.raw = value;
            return this;
        }

        public Builder payload(Map<String, Object> value) {
            this.payload = value == null ? Map.of() : value;
            return this;
        }

        public IndexableEvent build() {
            return new IndexableEvent(
                    eventId,
                    sourceId,
                    externalId,
                    occurredAt,
                    ingestedAt,
                    severity,
                    message,
                    raw,
                    text("format"),
                    text("host"),
                    text("srcIp"),
                    integer("srcPort"),
                    text("user"),
                    text("method"),
                    text("path"),
                    text("protocol"),
                    integer("status"),
                    number("bytes"),
                    text("referrer"),
                    text("userAgent"),
                    text("geoCountryIso"),
                    text("geoCountryName"),
                    text("geoCity"),
                    geoLatitude(),
                    geoLongitude(),
                    number("geoAsn"),
                    text("geoAsOrg"),
                    attributes());
        }

        private String text(String key) {
            Object value = payload.get(key);
            return value instanceof String s && !s.isBlank() ? s : null;
        }

        private Integer integer(String key) {
            Object value = payload.get(key);
            return value instanceof Number n ? n.intValue() : null;
        }

        private Long number(String key) {
            Object value = payload.get(key);
            return value instanceof Number n ? n.longValue() : null;
        }

        @SuppressWarnings("unchecked")
        private Map<String, Object> attributes() {
            Object value = payload.get("attributes");
            return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
        }

        private Double geoLatitude() {
            Object lat = geoLocation().get("lat");
            return lat instanceof Number n ? n.doubleValue() : null;
        }

        private Double geoLongitude() {
            Object lon = geoLocation().get("lon");
            return lon instanceof Number n ? n.doubleValue() : null;
        }

        private Map<?, ?> geoLocation() {
            Object value = payload.get("geoLocation");
            if (!(value instanceof Map<?, ?> map)) {
                return Map.of();
            }
            return map.get("lat") instanceof Number && map.get("lon") instanceof Number
                    ? map
                    : Map.of();
        }
    }
}
