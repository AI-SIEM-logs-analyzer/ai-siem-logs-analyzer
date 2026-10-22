package com.siem.analyzer.detect.sigma;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.StringJoiner;

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

    public record Meta(
            String title,
            String id,
            String name,
            String status,
            String description,
            String level,
            String author,
            List<String> references,
            List<String> falsepositives,
            List<String> tags) {

        public Meta {
            Objects.requireNonNull(title, "title");
            references = List.copyOf(references);
            falsepositives = List.copyOf(falsepositives);
            tags = List.copyOf(tags);
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
                    texts(document, "falsepositives"),
                    texts(document, "tags"));
        }
    }

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
