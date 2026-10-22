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

final class SigmaYaml {

    private static final YAMLMapper MAPPER =
            YAMLMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

    private SigmaYaml() {}

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

    static Map<String, Object> stringKeys(Map<?, ?> map) {
        Map<String, Object> copy = new LinkedHashMap<>();
        map.forEach((key, value) -> copy.put(String.valueOf(key), value));
        return copy;
    }
}
