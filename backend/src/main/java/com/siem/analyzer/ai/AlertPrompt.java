package com.siem.analyzer.ai;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.SerializableString;
import com.fasterxml.jackson.core.io.CharacterEscapes;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertRule;
import com.siem.analyzer.domain.LogEvent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public final class AlertPrompt {

    static final int MAX_VALUE_CHARS = 1_000;

    static final int MAX_RAW_CHARS = 4_000;

    static final int MAX_ENTRIES = 50;

    public static final int MAX_WINDOW_EVENTS = 20;

    static final int MAX_WINDOW_VALUE_CHARS = 300;

    private static final List<String> WINDOW_EVENT_FIELDS =
            List.of("srcIp", "user", "method", "path", "status", "bytes", "userAgent");

    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private static final ObjectMapper JSON = new ObjectMapper();

    static {
        JSON.enable(SerializationFeature.INDENT_OUTPUT);
        JSON.getFactory().setCharacterEscapes(new AngleBracketEscapes());
    }

    private final String text;
    private final String values;
    private final String normalisedText;

    private AlertPrompt(String text, String values) {
        this.text = text;
        this.values = values;
        this.normalisedText = normalise(text);
    }

    public static AlertPrompt of(Alert alert, List<LogEvent> windowEvents) {
        Objects.requireNonNull(alert, "alert");
        Objects.requireNonNull(windowEvents, "windowEvents");
        Map<String, Object> document = new LinkedHashMap<>();
        put(document, "title", alert.getTitle());
        put(document, "detail", alert.getDetail());
        put(document, "severity", alert.getSeverity());
        put(document, "raisedAt", alert.getRaisedAt());

        AlertRule rule = alert.getRule();
        if (rule != null) {
            Map<String, Object> ruleDocument = new LinkedHashMap<>();
            put(ruleDocument, "name", rule.getName());
            put(ruleDocument, "description", rule.getDescription());
            put(ruleDocument, "severity", rule.getSeverity());
            put(ruleDocument, "expression", rule.getExpression());
            document.put("rule", ruleDocument);
        }

        Map<String, Object> window = new LinkedHashMap<>();
        put(window, "eventCount", alert.getEventCount());
        put(window, "aggregateValue", alert.getAggregateValue());
        put(window, "start", alert.getWindowStart());
        put(window, "end", alert.getWindowEnd());
        put(window, "groupKey", alert.getGroupKey());
        if (!window.isEmpty()) {
            document.put("window", window);
        }

        LogEvent event = alert.getLogEvent();
        if (event != null) {
            Map<String, Object> trigger = new LinkedHashMap<>();
            if (event.getSource() != null) {
                put(trigger, "source", event.getSource().getName());
                put(trigger, "sourceType", event.getSource().getType());
            }
            put(trigger, "occurredAt", event.getOccurredAt());
            put(trigger, "severity", event.getSeverity());
            put(trigger, "message", event.getMessage());
            put(trigger, "fields", event.getPayload());
            if (event.getRaw() != null) {
                trigger.put("raw", cut(event.getRaw(), MAX_RAW_CHARS));
            }
            document.put("triggeringEvent", trigger);
        }

        List<Map<String, Object>> others =
                windowEvents.stream()
                        .filter(other -> other != event)
                        .filter(other -> event == null || !sameRow(other, event))
                        .limit(MAX_WINDOW_EVENTS)
                        .map(AlertPrompt::windowEvent)
                        .toList();
        if (!others.isEmpty()) {
            document.put("windowEvents", others);
        }

        try {
            return new AlertPrompt(JSON.writeValueAsString(document), values(document));
        } catch (JsonProcessingException e) {

            throw new IllegalStateException("could not write alert " + alert.getId(), e);
        }
    }

    public String text() {
        return text;
    }

    public boolean mentions(String quote) {
        if (quote == null || quote.isBlank()) {
            return false;
        }
        String normalised = normalise(quote);
        return values.contains(normalised) || normalisedText.contains(normalised);
    }

    String values() {
        return values;
    }

    private static boolean sameRow(LogEvent a, LogEvent b) {
        return a.getId() != null && a.getId().equals(b.getId());
    }

    private static Map<String, Object> windowEvent(LogEvent event) {
        Map<String, Object> written = new LinkedHashMap<>();
        put(written, "occurredAt", event.getOccurredAt());
        put(written, "severity", event.getSeverity());
        if (event.getMessage() != null) {
            written.put("message", cut(event.getMessage(), MAX_WINDOW_VALUE_CHARS));
        }
        Map<String, Object> payload = event.getPayload();
        if (payload != null) {
            for (String field : WINDOW_EVENT_FIELDS) {
                Object value = payload.get(field);
                if (value instanceof Number || value instanceof Boolean) {
                    written.put(field, value);
                } else if (value != null) {
                    written.put(field, cut(value.toString(), MAX_WINDOW_VALUE_CHARS));
                }
            }
        }
        return written;
    }

    private static void put(Map<String, Object> document, String key, Object value) {
        Object bounded = bound(value);
        if (bounded != null) {
            document.put(key, bounded);
        }
    }

    private static Object bound(Object value) {
        return switch (value) {
            case null -> null;
            case String text -> cut(text, MAX_VALUE_CHARS);
            case Number number -> number;
            case Boolean bool -> bool;
            case Instant instant -> instant.toString();
            case Enum<?> constant -> constant.name();
            case Map<?, ?> map -> boundMap(map);
            case Collection<?> collection -> boundList(collection);
            default -> cut(value.toString(), MAX_VALUE_CHARS);
        };
    }

    private static Map<String, Object> boundMap(Map<?, ?> map) {
        Map<String, Object> bounded = new LinkedHashMap<>();
        int written = 0;
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (written == MAX_ENTRIES) {
                bounded.put("…", (map.size() - written) + " more entries left out");
                break;
            }
            Object value = bound(entry.getValue());
            if (value != null) {
                bounded.put(cut(String.valueOf(entry.getKey()), MAX_VALUE_CHARS), value);
                written++;
            }
        }
        return bounded.isEmpty() ? null : bounded;
    }

    private static List<Object> boundList(Collection<?> collection) {
        List<Object> bounded =
                collection.stream()
                        .limit(MAX_ENTRIES)
                        .map(AlertPrompt::bound)
                        .filter(Objects::nonNull)
                        .collect(Collectors.toCollection(ArrayList::new));
        if (collection.size() > MAX_ENTRIES) {
            bounded.add((collection.size() - MAX_ENTRIES) + " more items left out");
        }
        return bounded;
    }

    private static String cut(String text, int max) {
        if (text.length() <= max) {
            return text;
        }
        return text.substring(0, max) + "…[" + (text.length() - max) + " more characters left out]";
    }

    private static String values(Object node) {
        StringBuilder lines = new StringBuilder();
        collect(node, lines);
        return lines.toString();
    }

    private static void collect(Object node, StringBuilder lines) {
        switch (node) {
            case Map<?, ?> map -> map.values().forEach(value -> collect(value, lines));
            case Collection<?> collection -> collection.forEach(value -> collect(value, lines));
            case null -> {}
            default -> lines.append(normalise(node.toString())).append('\n');
        }
    }

    private static String normalise(String text) {
        return WHITESPACE.matcher(text.strip()).replaceAll(" ");
    }

    private static final class AngleBracketEscapes extends CharacterEscapes {

        private final int[] escapes;

        AngleBracketEscapes() {
            escapes = CharacterEscapes.standardAsciiEscapesForJSON();
            escapes['<'] = CharacterEscapes.ESCAPE_STANDARD;
            escapes['>'] = CharacterEscapes.ESCAPE_STANDARD;
            escapes['&'] = CharacterEscapes.ESCAPE_STANDARD;
        }

        @Override
        public int[] getEscapeCodesForAscii() {
            return escapes;
        }

        @Override
        public SerializableString getEscapeSequence(int ch) {
            return null;
        }
    }
}
