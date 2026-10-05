package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * A field of a {@link NormalizedEvent} that a rule can read by name.
 *
 * <p>The standard fields are matched case-insensitively, so {@code srcip} and {@code srcIp} are the
 * same field. Anything else is reached through {@code attributes.<key>}, where the key is matched
 * exactly, as the source wrote it, and dots descend into nested JSON objects. Enums ({@code
 * severity}, {@code format}) read as their constant names.
 *
 * <p>{@code decodedPath} is the one derived field: {@code path} percent-decoded by {@link
 * UrlDecoding}, so a rule can match {@code ' OR 1=1} however the client encoded it while {@code
 * path} keeps what the server logged.
 *
 * <p>Two fields are equal when their names are, which is what lets a field serve in a group key.
 */
public final class EventField {

    /** The prefix that reaches into {@link NormalizedEvent#attributes()}. */
    public static final String ATTRIBUTES_PREFIX = "attributes.";

    private static final Map<String, EventField> STANDARD = standardFields();

    private final String name;
    private final Function<NormalizedEvent, Object> accessor;

    private EventField(String name, Function<NormalizedEvent, Object> accessor) {
        this.name = name;
        this.accessor = accessor;
    }

    /**
     * Resolves a field by name.
     *
     * @throws IllegalArgumentException no standard field has that name, and it does not start with
     *     {@value #ATTRIBUTES_PREFIX}
     */
    public static EventField named(String name) {
        EventField standard = STANDARD.get(name.toLowerCase(Locale.ROOT));
        if (standard != null) {
            return standard;
        }
        if (name.startsWith(ATTRIBUTES_PREFIX) && name.length() > ATTRIBUTES_PREFIX.length()) {
            String key = name.substring(ATTRIBUTES_PREFIX.length());
            return new EventField(name, event -> lookup(event.attributes(), key));
        }
        throw new IllegalArgumentException(
                "unknown field '"
                        + name
                        + "'; expected one of "
                        + STANDARD.values().stream().map(EventField::name).toList()
                        + " or "
                        + ATTRIBUTES_PREFIX
                        + "<key>");
    }

    /** The name as the rule spells it, for a standard field its canonical camelCase spelling. */
    public String name() {
        return name;
    }

    /** The field's value on {@code event}, or {@code null} when the event does not carry it. */
    public Object read(NormalizedEvent event) {
        return accessor.apply(event);
    }

    /**
     * Finds {@code key} in {@code map}, descending into nested maps at dots.
     *
     * <p>A key that itself contains dots is tried whole first, so a flat {@code "http.method"} key
     * and a nested {@code {"http": {"method": …}}} are both found by {@code
     * attributes.http.method}.
     */
    private static Object lookup(Map<?, ?> map, String key) {
        if (map.containsKey(key)) {
            return map.get(key);
        }
        for (int dot = key.indexOf('.'); dot > 0; dot = key.indexOf('.', dot + 1)) {
            if (map.get(key.substring(0, dot)) instanceof Map<?, ?> nested) {
                Object found = lookup(nested, key.substring(dot + 1));
                if (found != null) {
                    return found;
                }
            }
        }
        return null;
    }

    private static Map<String, EventField> standardFields() {
        Map<String, EventField> fields = new LinkedHashMap<>();
        put(fields, "host", NormalizedEvent::host);
        put(fields, "srcIp", NormalizedEvent::srcIp);
        put(fields, "srcPort", NormalizedEvent::srcPort);
        put(fields, "user", NormalizedEvent::user);
        put(fields, "method", NormalizedEvent::method);
        put(fields, "path", NormalizedEvent::path);
        put(fields, "decodedPath", event -> UrlDecoding.decode(event.path()));
        put(fields, "protocol", NormalizedEvent::protocol);
        put(fields, "status", NormalizedEvent::status);
        put(fields, "bytes", NormalizedEvent::bytes);
        put(fields, "referrer", NormalizedEvent::referrer);
        put(fields, "userAgent", NormalizedEvent::userAgent);
        put(fields, "severity", event -> event.severity().name());
        put(fields, "format", event -> event.format().name());
        put(fields, "message", NormalizedEvent::message);
        return Map.copyOf(fields);
    }

    private static void put(
            Map<String, EventField> fields,
            String name,
            Function<NormalizedEvent, Object> accessor) {
        fields.put(name.toLowerCase(Locale.ROOT), new EventField(name, accessor));
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof EventField field && name.equals(field.name);
    }

    @Override
    public int hashCode() {
        return name.hashCode();
    }

    @Override
    public String toString() {
        return name;
    }
}
