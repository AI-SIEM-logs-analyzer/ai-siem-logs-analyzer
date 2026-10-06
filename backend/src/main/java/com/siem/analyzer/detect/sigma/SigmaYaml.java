package com.siem.analyzer.detect.sigma;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reads a YAML stream into plain {@link Map}s, {@link List}s and scalars, one per document.
 *
 * <p>Jackson binds no types here, so a rule file cannot make the reader instantiate anything; the
 * SnakeYAML limits underneath (document size, alias expansion) stay at their defaults. Duplicate
 * keys are an error rather than last-one-wins, because in a detection a silently dropped selection
 * changes what the rule matches. Unquoted {@code yes}, {@code no} and dates stay strings, as Sigma
 * expects.
 */
final class SigmaYaml {

    private static final YAMLMapper MAPPER =
            YAMLMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    private SigmaYaml() {}

    /**
     * The documents of {@code yaml}, in order, empty documents left out.
     *
     * @throws SigmaException the text is not YAML, or a document is not a mapping
     */
    static List<Map<String, Object>> read(String yaml) {
        List<Map<String, Object>> documents = new ArrayList<>();
        try (MappingIterator<Object> values = MAPPER.readerFor(Object.class).readValues(yaml)) {
            while (values.hasNextValue()) {
                Object document = values.nextValue();
                if (document == null) {
                    continue;
                }
                if (!(document instanceof Map<?, ?> map)) {
                    throw new SigmaException(
                            "document " + (documents.size() + 1) + " is not a YAML mapping");
                }
                documents.add(stringKeys(map));
            }
        } catch (JsonProcessingException e) {
            throw new SigmaException("not valid YAML: " + e.getOriginalMessage());
        } catch (IOException e) {
            throw new SigmaException("not valid YAML: " + e.getMessage());
        }
        return documents;
    }

    /** YAML allows any scalar as a key; Sigma's are all text, so a number key is read as one. */
    static Map<String, Object> stringKeys(Map<?, ?> map) {
        Map<String, Object> copy = new LinkedHashMap<>();
        map.forEach((key, value) -> copy.put(String.valueOf(key), value));
        return copy;
    }
}
