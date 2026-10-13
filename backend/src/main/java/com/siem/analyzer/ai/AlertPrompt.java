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
import java.util.stream.Collectors;

/**
 * Writes an alert and its evidence as the JSON document {@link AlertSummarizer} reads.
 *
 * <p>The document is JSON so that nothing in it can pose as structure: a log line is attacker
 * input, and as a JSON string a newline in it stays {@code \n} and a {@code </alert>} in it is
 * written {@code </alert>}, so it can neither close the {@code <alert>} block the prompt wraps it
 * in nor start one of its own.
 *
 * <p>Every string is capped at {@link #MAX_VALUE_CHARS} (the raw line at {@link #MAX_RAW_CHARS})
 * and a map at {@link #MAX_ENTRIES} entries, and a cut says how much it left out, so a 50 MB line
 * costs the same prompt as a short one and the model knows it saw only part of it.
 */
public final class AlertPrompt {

    /** Longest string value written as is. */
    static final int MAX_VALUE_CHARS = 1_000;

    /** Longest raw log line written as is. */
    static final int MAX_RAW_CHARS = 4_000;

    /** Most entries written from one map, such as the event's attributes. */
    static final int MAX_ENTRIES = 50;

    private static final ObjectMapper JSON = new ObjectMapper();

    static {
        JSON.enable(SerializationFeature.INDENT_OUTPUT);
        JSON.getFactory().setCharacterEscapes(new AngleBracketEscapes());
    }

    private AlertPrompt() {}

    /**
     * The alert as a JSON document.
     *
     * <p>Reads the alert's rule and triggering event and that event's source, so call it while they
     * can still be loaded.
     */
    public static String render(Alert alert) {
        Objects.requireNonNull(alert, "alert");
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

        try {
            return JSON.writeValueAsString(document);
        } catch (JsonProcessingException e) {
            // Only maps, lists, strings, numbers and booleans reach the mapper.
            throw new IllegalStateException("could not write alert " + alert.getId(), e);
        }
    }

    private static void put(Map<String, Object> document, String key, Object value) {
        Object bounded = bound(value);
        if (bounded != null) {
            document.put(key, bounded);
        }
    }

    /** {@code value} as plain JSON values, with every string, map and list capped. */
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

    /**
     * Escapes {@code <}, {@code >} and {@code &} as {@code \}{@code u} sequences, the way JSON
     * embedded in HTML is made safe, so no value can write a tag.
     */
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
