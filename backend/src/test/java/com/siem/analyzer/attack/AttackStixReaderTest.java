package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/** The STIX bundle reader, on the hand-written fixture and on what it must refuse. */
class AttackStixReaderTest {

    private static final long NO_LIMIT = Long.MAX_VALUE;

    private static AttackBundle read(byte[] bytes) {
        return AttackStixReader.read(new ByteArrayInputStream(bytes), NO_LIMIT);
    }

    private static AttackBundle read(String json) {
        return read(json.getBytes(StandardCharsets.UTF_8));
    }

    private static Map<String, AttackBundle.Technique> byId(AttackBundle bundle) {
        return bundle.techniques().stream()
                .collect(Collectors.toMap(AttackBundle.Technique::id, Function.identity()));
    }

    @Test
    void readsTacticsInMatrixOrder() {
        AttackBundle bundle = read(AttackFixtures.bytes());

        assertEquals(
                List.of("TA0043", "TA0001", "TA0006", "TA0005", "TA0007"),
                bundle.tactics().stream().map(AttackBundle.Tactic::id).toList());
        assertEquals(
                List.of(1, 2, 3, 4, 5),
                bundle.tactics().stream().map(AttackBundle.Tactic::ordinal).toList());
        AttackBundle.Tactic credentials = bundle.tactics().get(2);
        assertEquals("Credential Access", credentials.name());
        assertEquals("credential-access", credentials.shortname());
        assertEquals("https://attack.mitre.org/tactics/TA0006", credentials.url());
    }

    @Test
    void keepsOnlyCurrentEnterpriseTechniquesInIdOrder() {
        AttackBundle bundle = read(AttackFixtures.bytes());

        assertEquals(
                List.of(
                        "T1078",
                        "T1083",
                        "T1110",
                        "T1110.001",
                        "T1110.003",
                        "T1110.004",
                        "T1190",
                        "T1595",
                        "T1595.002",
                        "T1595.003"),
                bundle.techniques().stream().map(AttackBundle.Technique::id).toList());
        assertEquals(AttackFixtures.TECHNIQUE_COUNT, bundle.techniques().size());
    }

    @Test
    void readsASubTechniqueWithItsParent() {
        AttackBundle.Technique guessing = byId(read(AttackFixtures.bytes())).get("T1110.001");

        assertEquals("Password Guessing", guessing.name());
        assertEquals("T1110", guessing.parentId());
        assertEquals("https://attack.mitre.org/techniques/T1110/001", guessing.url());
        assertEquals(List.of("TA0006"), guessing.tacticIds());
        assertNull(byId(read(AttackFixtures.bytes())).get("T1110").parentId());
    }

    @Test
    void aTechniqueMayBelongToSeveralTactics() {
        assertEquals(
                List.of("TA0001", "TA0005"),
                byId(read(AttackFixtures.bytes())).get("T1078").tacticIds());
    }

    @Test
    void recordsTheVersionAndTheChecksumOfTheJson() throws NoSuchAlgorithmException {
        byte[] json = AttackFixtures.bytes();

        AttackBundle bundle = read(json);

        assertEquals("0.1", bundle.version());
        assertEquals(
                HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(json)),
                bundle.sha256());
    }

    @Test
    void readsAGzippedBundleToTheSameResult() {
        byte[] json = AttackFixtures.bytes();

        assertEquals(read(json), read(AttackFixtures.gzip(json)));
    }

    @Test
    void dropsALinkThatDoesNotPointAtMitre() {
        String bundle =
                new String(AttackFixtures.bytes(), StandardCharsets.UTF_8)
                        .replace(
                                "\"https://attack.mitre.org/techniques/T1083\"",
                                "\"javascript:alert(1)\"");

        AttackBundle.Technique discovery = byId(read(bundle)).get("T1083");

        assertNull(discovery.url());
        assertEquals("File and Directory Discovery", discovery.name());
    }

    @Test
    void refusesWhatIsNotAnAttackBundle() {
        List<String> refused =
                List.of(
                        "",
                        "[]",
                        "{\"type\":\"report\",\"objects\":[]}",
                        "{\"type\":\"bundle\"}",
                        "{\"type\":\"bundle\",\"objects\":{}}",
                        "{\"type\":\"bundle\",\"objects\":[]}",
                        "{\"type\":\"bundle\",\"objects\":[{\"type\":\"x-mitre-collection\",",
                        "{\"type\":\"bundle\",\"objects\":[{\"type\":\"x-mitre-collection\","
                                + "\"x_mitre_version\":\"1.0\"}]}");
        for (String json : refused) {
            assertThrows(InvalidAttackBundleException.class, () -> read(json), json);
        }
    }

    @Test
    void refusesAMalformedTechniqueId() {
        String bundle =
                new String(AttackFixtures.bytes(), StandardCharsets.UTF_8)
                        .replace("\"external_id\": \"T1083\"", "\"external_id\": \"T10833\"");

        InvalidAttackBundleException refused =
                assertThrows(InvalidAttackBundleException.class, () -> read(bundle));
        assertTrue(refused.getMessage().contains("T10833"), refused.getMessage());
    }

    @Test
    void refusesABundleLargerThanTheLimitOnceDecompressed() {
        byte[] gzipped = AttackFixtures.gzip(AttackFixtures.bytes());

        InvalidAttackBundleException refused =
                assertThrows(
                        InvalidAttackBundleException.class,
                        () -> AttackStixReader.read(new ByteArrayInputStream(gzipped), 1_000));
        assertTrue(refused.getMessage().contains("1000 bytes"), refused.getMessage());
    }
}
