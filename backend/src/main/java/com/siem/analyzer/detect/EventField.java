package com.siem.analyzer.detect;

import com.siem.analyzer.domain.NormalizedEvent;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

public final class EventField {

    public static final String ATTRIBUTES_PREFIX = "attributes.";

    private static final Map<String, EventField> STANDARD = standardFields();

    private final String name;
    private final Function<NormalizedEvent, Object> accessor;

    private EventField(String name, Function<NormalizedEvent, Object> accessor) {
        this.name = name;
        this.accessor = accessor;
    }

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

    public String name() {
        return name;
    }

    public Object read(NormalizedEvent event) {
        return accessor.apply(event);
    }

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
        put(fields, "uriStem", event -> uriStem(event.path()));
        put(fields, "uriQuery", event -> uriQuery(event.path()));
        put(fields, "protocol", NormalizedEvent::protocol);
        put(fields, "status", NormalizedEvent::status);
        put(fields, "bytes", NormalizedEvent::bytes);
        put(fields, "referrer", NormalizedEvent::referrer);
        put(fields, "userAgent", NormalizedEvent::userAgent);
        put(fields, "severity", event -> event.severity().name());
        put(fields, "format", event -> event.format().name());
        put(fields, "message", NormalizedEvent::message);
        put(fields, "raw", NormalizedEvent::raw);
        return Map.copyOf(fields);
    }

    private static String uriStem(String path) {
        if (path == null) {
            return null;
        }
        int query = path.indexOf('?');
        return query < 0 ? path : query == 0 ? null : path.substring(0, query);
    }

    private static String uriQuery(String path) {
        int query = path == null ? -1 : path.indexOf('?');
        return query < 0 || query == path.length() - 1 ? null : path.substring(query + 1);
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
