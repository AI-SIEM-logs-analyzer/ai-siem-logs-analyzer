package com.siem.analyzer.attack;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.AttackDataset;
import com.siem.analyzer.repo.AttackTechniqueRepository;
import com.siem.analyzer.service.PayloadTooLargeException;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Importing the dataset. Each import commits, so every test leaves the fixture loaded again for the
 * classes that run after it.
 */
@QuarkusTest
class AttackDatasetServiceTest {

    @Inject AttackDatasetService datasets;
    @Inject AttackTechniqueRepository techniques;
    @Inject EntityManager entityManager;
    @Inject AppConfig appConfig;

    @AfterEach
    void restoreTheFixture() {
        datasets.importUpload(new ByteArrayInputStream(AttackFixtures.bytes()));
    }

    private void storedVersion(String version) {
        QuarkusTransaction.requiringNew()
                .run(
                        () ->
                                entityManager
                                        .createNativeQuery("update attack_dataset set version = ?1")
                                        .setParameter(1, version)
                                        .executeUpdate());
    }

    private void nothingStored() {
        QuarkusTransaction.requiringNew()
                .run(
                        () -> {
                            techniques.deleteDataset();
                            entityManager
                                    .createNativeQuery("delete from attack_dataset")
                                    .executeUpdate();
                        });
    }

    private String version() {
        return datasets.current().map(AttackDataset::getVersion).orElse(null);
    }

    private long techniqueCount() {
        return QuarkusTransaction.requiringNew().call(() -> techniques.count());
    }

    @Test
    void importsTheBundledReleaseWhenNothingIsStored() {
        nothingStored();

        assertEquals(AttackDatasetService.Outcome.IMPORTED, datasets.importBundledIfNewer());

        assertEquals("0.1", version());
        assertEquals(AttackFixtures.TECHNIQUE_COUNT, techniqueCount());
        assertEquals(
                AttackFixtures.TECHNIQUE_COUNT,
                datasets.current().orElseThrow().getTechniqueCount());
    }

    @Test
    void leavesTheSameReleaseAlone() {
        assertEquals(AttackDatasetService.Outcome.CURRENT, datasets.importBundledIfNewer());
    }

    @Test
    void upgradesAnOlderRelease() {
        storedVersion("0.0");

        assertEquals(AttackDatasetService.Outcome.IMPORTED, datasets.importBundledIfNewer());
        assertEquals("0.1", version());
    }

    @Test
    void keepsANewerReleaseAnAdministratorUploaded() {
        storedVersion("99.0");

        assertEquals(AttackDatasetService.Outcome.CURRENT, datasets.importBundledIfNewer());
        assertEquals("99.0", version());
    }

    @Test
    void anUploadReplacesTheDatasetWhateverItsVersion() {
        storedVersion("99.0");

        AttackDataset imported =
                datasets.importUpload(
                        new ByteArrayInputStream(AttackFixtures.gzip(AttackFixtures.bytes())));

        assertEquals("0.1", imported.getVersion());
        assertEquals("0.1", version());
    }

    @Test
    void aRefusedUploadLeavesTheStoredDatasetAsItWas() {
        byte[] notABundle = "{\"type\":\"bundle\",\"objects\":[]}".getBytes(StandardCharsets.UTF_8);

        assertThrows(
                InvalidAttackBundleException.class,
                () -> datasets.importUpload(new ByteArrayInputStream(notABundle)));

        assertEquals("0.1", version());
        assertEquals(AttackFixtures.TECHNIQUE_COUNT, techniqueCount());
    }

    @Test
    void readsAnUploadUpToTheLimitAndNoFurther() {
        byte[] ten = new byte[10];

        assertArrayEquals(ten, AttackDatasetService.readAtMost(new ByteArrayInputStream(ten), 10));
        assertThrows(
                PayloadTooLargeException.class,
                () -> AttackDatasetService.readAtMost(new ByteArrayInputStream(new byte[11]), 10));
    }

    @Test
    void aFailedStartUpImportIsLoggedNotThrown() {
        AttackDatasetService failing =
                new AttackDatasetService(null, null, null, appConfig) {
                    @Override
                    public Outcome importBundledIfNewer() {
                        throw new InvalidAttackBundleException("broken bundle");
                    }
                };

        assertDoesNotThrow(() -> new AttackDatasetInitializer(failing, appConfig).onStart(null));
    }
}
