package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import org.junit.jupiter.api.Test;

/**
 * Verifies that Flyway owns the schema and that the initial migration ran.
 *
 * <p>These assertions go through the database rather than through entities on purpose: they have to
 * keep working even if every entity mapping is later changed.
 */
@QuarkusTest
class FlywayMigrationTest {

    @Inject EntityManager entityManager;

    @Test
    @TestTransaction
    void initialMigrationIsRecordedAsSuccessful() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select version, success from flyway_schema_history"
                                                + " where version = '1'")
                                .getSingleResult();

        assertEquals("1", row[0]);
        assertEquals(Boolean.TRUE, row[1]);
    }

    @Test
    @TestTransaction
    void usersMigrationIsRecordedAsSuccessful() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select version, success from flyway_schema_history"
                                                + " where version = '2'")
                                .getSingleResult();

        assertEquals("2", row[0]);
        assertEquals(Boolean.TRUE, row[1]);
    }

    @Test
    @TestTransaction
    void everyCoreTableExists() {
        Long count =
                (Long)
                        entityManager
                                .createNativeQuery(
                                        "select count(*) from information_schema.tables"
                                                + " where table_schema = 'public'"
                                                + " and table_name in ('log_source', 'log_event',"
                                                + " 'alert_rule', 'alert', 'app_user',"
                                                + " 'user_role')")
                                .getSingleResult();

        assertEquals(6L, count);
    }
}
