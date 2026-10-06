package com.siem.analyzer.detect.sigma;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

/**
 * One Sigma detection rule, as read from YAML and before any conversion.
 *
 * <p>Only what conversion and the stored description need is kept. The detection's search
 * identifiers stay as the YAML tree Jackson produced, since what a value means depends on the
 * modifiers on its key and is decided by {@link SigmaConverter}.
 *
 * @param meta title, identity and the other descriptive keys
 * @param logsource what the rule was written against
 * @param searches the detection's search identifiers in file order, {@code condition} excluded
 * @param conditions the detection's condition, one entry per list item; several are ORed
 * @param timeframe the window of a Sigma 1 aggregation such as {@code | count() by c-ip > 10}, as
 *     written ({@code 5m}); {@code null} when absent
 */
public record SigmaRule(
        Meta meta,
        Logsource logsource,
        Map<String, Object> searches,
        List<String> conditions,
        String timeframe) {

    public SigmaRule {
        Objects.requireNonNull(meta, "meta");
        Objects.requireNonNull(logsource, "logsource");
        searches = Collections.unmodifiableMap(new LinkedHashMap<>(searches));
        conditions = List.copyOf(conditions);
    }

    /**
     * The keys every Sigma document carries, rule or correlation.
     *
     * @param title required
     * @param id a UUID by convention; {@code null} when absent
     * @param name the handle a correlation refers to the rule by; {@code null} when absent
     * @param status {@code stable}, {@code test}, {@code experimental}, {@code deprecated} or
     *     {@code unsupported}; {@code null} when absent
     * @param level {@code informational}, {@code low}, {@code medium}, {@code high} or {@code
     *     critical}; {@code null} when absent
     */
    public record Meta(
            String title,
            String id,
            String name,
            String status,
            String description,
            String level,
            String author,
            List<String> references,
            List<String> falsepositives) {

        public Meta {
            Objects.requireNonNull(title, "title");
            references = List.copyOf(references);
            falsepositives = List.copyOf(falsepositives);
        }

        static Meta from(Map<String, Object> document) {
            String title = text(document, "title");
            if (title == null || title.isBlank()) {
                throw new SigmaException("the rule has no title");
            }
            return new Meta(
                    title.strip(),
                    text(document, "id"),
                    text(document, "name"),
                    text(document, "status"),
                    text(document, "description"),
                    text(document, "level"),
                    text(document, "author"),
                    texts(document, "references"),
                    texts(document, "falsepositives"));
        }
    }

    /** The {@code logsource} block; each key {@code null} when the rule leaves it out. */
    public record Logsource(String category, String product, String service) {

        @Override
        public String toString() {
            StringJoiner text = new StringJoiner(", ", "{", "}");
            if (category != null) {
                text.add("category: " + category);
            }
            if (product != null) {
                text.add("product: " + product);
            }
            if (service != null) {
                text.add("service: " + service);
            }
            return text.toString();
        }
    }

    /**
     * Reads a rule document.
     *
     * @throws SigmaException a required key is missing or has the wrong shape
     */
    static SigmaRule from(Map<String, Object> document) {
        Meta meta = Meta.from(document);
        Logsource logsource = new Logsource(null, null, null);
        Object logsourceBlock = document.get("logsource");
        if (logsourceBlock instanceof Map<?, ?> map) {
            Map<String, Object> keys = SigmaYaml.stringKeys(map);
            logsource =
                    new Logsource(
                            text(keys, "category"), text(keys, "product"), text(keys, "service"));
        } else if (logsourceBlock != null) {
            throw new SigmaException("'logsource' is not a mapping");
        }

        if (!(document.get("detection") instanceof Map<?, ?> detectionBlock)) {
            throw new SigmaException("the rule has no 'detection' mapping");
        }
        Map<String, Object> searches = SigmaYaml.stringKeys(detectionBlock);
        Object condition = searches.remove("condition");
        List<String> conditions = new ArrayList<>();
        if (condition instanceof String single) {
            conditions.add(single);
        } else if (condition instanceof List<?> list) {
            for (Object item : list) {
                if (!(item instanceof String text)) {
                    throw new SigmaException("a 'condition' list holds something other than text");
                }
                conditions.add(text);
            }
        }
        if (conditions.isEmpty() || conditions.stream().anyMatch(String::isBlank)) {
            throw new SigmaException("the detection has no 'condition'");
        }
        if (searches.isEmpty()) {
            throw new SigmaException("the detection defines no search identifiers");
        }
        return new SigmaRule(meta, logsource, searches, conditions, text(document, "timeframe"));
    }

    /** A scalar value as text, or {@code null} when absent; a mapping or a list is an error. */
    static String text(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Map<?, ?> || value instanceof List<?>) {
            throw new SigmaException("'" + key + "' is not a single value");
        }
        String text = String.valueOf(value).strip();
        return text.isEmpty() ? null : text;
    }

    /** A list of scalars as text, a lone scalar as a list of one; empty when absent. */
    static List<String> texts(Map<String, Object> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return List.of();
        }
        List<?> items = value instanceof List<?> list ? list : List.of(value);
        List<String> texts = new ArrayList<>(items.size());
        for (Object item : items) {
            if (item instanceof Map<?, ?> || item instanceof List<?>) {
                throw new SigmaException("'" + key + "' holds something other than text");
            }
            if (item != null && !String.valueOf(item).isBlank()) {
                texts.add(String.valueOf(item).strip());
            }
        }
        return texts;
    }
}
