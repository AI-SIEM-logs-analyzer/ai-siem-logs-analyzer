package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.siem.analyzer.detect.BruteForceLoginRule;
import com.siem.analyzer.detect.PathTraversalRule;
import com.siem.analyzer.detect.ScannerUserAgentRule;
import com.siem.analyzer.detect.SqlInjectionRule;
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
    void authEventsMigrationIsRecordedAsSuccessful() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select version, success from flyway_schema_history"
                                                + " where version = '3'")
                                .getSingleResult();

        assertEquals("3", row[0]);
        assertEquals(Boolean.TRUE, row[1]);
    }

    @Test
    @TestTransaction
    void logUploadsMigrationIsRecordedAsSuccessful() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select version, success from flyway_schema_history"
                                                + " where version = '4'")
                                .getSingleResult();

        assertEquals("4", row[0]);
        assertEquals(Boolean.TRUE, row[1]);
    }

    @Test
    @TestTransaction
    void bruteForceLoginRuleIsSeededAsTheEngineDefinesIt() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select severity, expression, enabled from alert_rule"
                                                + " where name = :name")
                                .setParameter("name", BruteForceLoginRule.NAME)
                                .getSingleResult();

        assertEquals(BruteForceLoginRule.SEVERITY.name(), row[0]);
        assertEquals(BruteForceLoginRule.EXPRESSION, row[1]);
        assertEquals(Boolean.TRUE, row[2]);
    }

    @Test
    @TestTransaction
    void sqlInjectionRuleIsSeededAsTheEngineDefinesIt() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select severity, expression, enabled from alert_rule"
                                                + " where name = :name")
                                .setParameter("name", SqlInjectionRule.NAME)
                                .getSingleResult();

        assertEquals(SqlInjectionRule.SEVERITY.name(), row[0]);
        assertEquals(SqlInjectionRule.EXPRESSION, row[1]);
        assertEquals(Boolean.TRUE, row[2]);
    }

    @Test
    @TestTransaction
    void pathTraversalRuleIsSeededAsTheEngineDefinesIt() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select severity, expression, enabled from alert_rule"
                                                + " where name = :name")
                                .setParameter("name", PathTraversalRule.NAME)
                                .getSingleResult();

        assertEquals(PathTraversalRule.SEVERITY.name(), row[0]);
        assertEquals(PathTraversalRule.EXPRESSION, row[1]);
        assertEquals(Boolean.TRUE, row[2]);
    }

    @Test
    @TestTransaction
    void scannerUserAgentRuleIsSeededAsTheEngineDefinesIt() {
        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "select severity, expression, enabled from alert_rule"
                                                + " where name = :name")
                                .setParameter("name", ScannerUserAgentRule.NAME)
                                .getSingleResult();

        assertEquals(ScannerUserAgentRule.SEVERITY.name(), row[0]);
        assertEquals(ScannerUserAgentRule.EXPRESSION, row[1]);
        assertEquals(Boolean.TRUE, row[2]);
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
                                                + " 'user_role', 'auth_event', 'log_upload')")
                                .getSingleResult();

        assertEquals(8L, count);
    }
}
