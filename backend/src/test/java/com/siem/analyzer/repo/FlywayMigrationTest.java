package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.siem.analyzer.detect.BruteForceLoginRule;
import com.siem.analyzer.detect.PathTraversalRule;
import com.siem.analyzer.detect.ScannerUserAgentRule;
import com.siem.analyzer.detect.SqlInjectionRule;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceException;
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

    /** Inserts a log event through SQL alone and returns its id. */
    private Long insertedLogEvent() {
        Number sourceId =
                (Number)
                        entityManager
                                .createNativeQuery(
                                        "insert into log_source (name, type)"
                                                + " values ('flyway-alert-source', 'SYSLOG')"
                                                + " returning id")
                                .getSingleResult();
        Number eventId =
                (Number)
                        entityManager
                                .createNativeQuery(
                                        "insert into log_event"
                                                + " (source_id, occurred_at, severity, message, raw)"
                                                + " values (?1, now(), 'INFO', 'm', 'r')"
                                                + " returning id")
                                .setParameter(1, sourceId.longValue())
                                .getSingleResult();
        return eventId.longValue();
    }

    @Test
    @TestTransaction
    void anAlertInsertedWithoutAStatusStartsAsNew() {
        Long eventId = insertedLogEvent();

        Object[] row =
                (Object[])
                        entityManager
                                .createNativeQuery(
                                        "insert into alert (log_event_id, title, severity)"
                                                + " values (?1, 't', 'INFO')"
                                                + " returning status, status_changed_at")
                                .setParameter(1, eventId)
                                .getSingleResult();

        assertEquals("NEW", row[0]);
        assertNotNull(row[1]);
    }

    @Test
    @TestTransaction
    void theStatusConstraintRefusesTheRetiredNames() {
        Long eventId = insertedLogEvent();

        assertThrows(
                PersistenceException.class,
                () ->
                        entityManager
                                .createNativeQuery(
                                        "insert into alert (log_event_id, title, severity, status)"
                                                + " values (?1, 't', 'INFO', 'OPEN')")
                                .setParameter(1, eventId)
                                .executeUpdate());
    }

    @Test
    @TestTransaction
    void aClosedAlertMustCarryItsCloseTime() {
        Long eventId = insertedLogEvent();

        assertThrows(
                PersistenceException.class,
                () ->
                        entityManager
                                .createNativeQuery(
                                        "insert into alert (log_event_id, title, severity, status)"
                                                + " values (?1, 't', 'INFO', 'RESOLVED')")
                                .setParameter(1, eventId)
                                .executeUpdate());
    }

    @Test
    @TestTransaction
    void anOpenAlertMayNotCarryACloseTime() {
        Long eventId = insertedLogEvent();

        assertThrows(
                PersistenceException.class,
                () ->
                        entityManager
                                .createNativeQuery(
                                        "insert into alert"
                                                + " (log_event_id, title, severity, status,"
                                                + " resolved_at)"
                                                + " values (?1, 't', 'INFO', 'IN_PROGRESS', now())")
                                .setParameter(1, eventId)
                                .executeUpdate());
    }
}
