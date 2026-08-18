package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.PersistenceException;
import org.junit.jupiter.api.Test;

/** Persistence behaviour of {@link LogSource}, exercised against the real schema. */
@QuarkusTest
class LogSourceRepositoryTest {

    @Inject LogSourceRepository repository;

    private static LogSource source(String name) {
        LogSource logSource = new LogSource();
        logSource.setName(name);
        logSource.setType(LogSourceType.FIREWALL);
        logSource.setHostname("edge-fw-01");
        return logSource;
    }

    @Test
    @TestTransaction
    void persistsAndReadsBackAllFields() {
        LogSource stored = source("edge-firewall");

        repository.persist(stored);
        repository.flush();

        LogSource found = repository.findById(stored.getId());
        assertNotNull(found.getId());
        assertEquals("edge-firewall", found.getName());
        assertEquals(LogSourceType.FIREWALL, found.getType());
        assertEquals("edge-fw-01", found.getHostname());
        // Defaults are assigned in Java rather than left to the column default: Hibernate
        // sends every mapped column on insert, so a null field would override the default.
        assertTrue(found.isEnabled());
        assertNotNull(found.getCreatedAt());
    }

    @Test
    @TestTransaction
    void findsBySourceName() {
        repository.persist(source("cloudtrail-prod"));
        repository.flush();

        assertTrue(repository.findByName("cloudtrail-prod").isPresent());
        assertTrue(repository.findByName("does-not-exist").isEmpty());
    }

    @Test
    @TestTransaction
    void listsOnlyEnabledSources() {
        LogSource enabled = source("enabled-source");
        LogSource disabled = source("disabled-source");
        disabled.setEnabled(false);

        repository.persist(enabled);
        repository.persist(disabled);
        repository.flush();

        assertEquals(1, repository.listEnabled().size());
        assertEquals("enabled-source", repository.listEnabled().get(0).getName());
    }

    @Test
    @TestTransaction
    void rejectsADuplicateName() {
        repository.persist(source("duplicate"));
        repository.flush();

        assertThrows(
                PersistenceException.class,
                () -> {
                    repository.persist(source("duplicate"));
                    repository.flush();
                });
    }
}
