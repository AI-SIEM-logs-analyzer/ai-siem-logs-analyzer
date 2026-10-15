package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * The release shipped in the jar. The suite boots on a small fixture instead, so this is the one
 * place the real file is parsed: it proves the file reads, and that every ID this application maps
 * is in it.
 */
class BundledAttackDatasetTest {

    private static final String RESOURCE = "/mitre/enterprise-attack-19.2.json.gz";

    private static AttackBundle bundle;
    private static Map<String, AttackBundle.Technique> byId;

    @BeforeAll
    static void read() throws IOException {
        try (InputStream in = BundledAttackDatasetTest.class.getResourceAsStream(RESOURCE)) {
            assertNotNull(in, RESOURCE + " is missing from the main resources");
            bundle = AttackStixReader.read(in, 268_435_456L);
        }
        byId =
                bundle.techniques().stream()
                        .collect(Collectors.toMap(AttackBundle.Technique::id, Function.identity()));
    }

    @Test
    void isTheReleaseTheConfigurationNames() {
        assertEquals("19.2", bundle.version());
        assertEquals(
                "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",
                bundle.sha256());
    }

    @Test
    void holdsTheEnterpriseMatrix() {
        assertTrue(bundle.tactics().size() >= 14, "tactics: " + bundle.tactics().size());
        assertTrue(bundle.techniques().size() > 600, "techniques: " + bundle.techniques().size());
        assertEquals("Password Guessing", byId.get("T1110.001").name());
        assertEquals(List.of("TA0006"), byId.get("T1110.001").tacticIds());
    }

    @Test
    void knowsEveryTechniqueTheBuiltInRulesMap() {
        for (String id :
                Set.of("T1110.001", "T1110.003", "T1190", "T1083", "T1595.002", "T1595.003")) {
            assertTrue(byId.containsKey(id), id);
        }
    }

    @Test
    void knowsEveryTechniqueTheAttackTypeFallbackNames() {
        for (String id : AttackTypeTechniques.allTechniqueIds()) {
            assertTrue(byId.containsKey(id), id);
        }
    }
}
