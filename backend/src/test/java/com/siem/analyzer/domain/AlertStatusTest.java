package com.siem.analyzer.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** The triage lifecycle: which moves {@link AlertStatus} allows and what a move records. */
class AlertStatusTest {

    private static final Instant T0 = Instant.parse("2026-10-06T10:00:00Z");

    private static final Map<AlertStatus, Set<AlertStatus>> ALLOWED =
            Map.of(
                    AlertStatus.NEW,
                    EnumSet.of(
                            AlertStatus.IN_PROGRESS,
                            AlertStatus.RESOLVED,
                            AlertStatus.FALSE_POSITIVE),
                    AlertStatus.IN_PROGRESS,
                    EnumSet.of(AlertStatus.NEW, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE),
                    AlertStatus.RESOLVED,
                    EnumSet.of(AlertStatus.IN_PROGRESS),
                    AlertStatus.FALSE_POSITIVE,
                    EnumSet.of(AlertStatus.IN_PROGRESS));

    @Test
    void allowsExactlyTheDocumentedTransitions() {
        for (AlertStatus from : AlertStatus.values()) {
            for (AlertStatus to : AlertStatus.values()) {
                assertEquals(
                        ALLOWED.get(from).contains(to), from.canMoveTo(to), from + " -> " + to);
            }
        }
    }

    @Test
    void neverAllowsStayingPut() {
        for (AlertStatus status : AlertStatus.values()) {
            assertFalse(status.canMoveTo(status), status.name());
        }
    }

    @Test
    void onlyResolvedAndFalsePositiveAreClosed() {
        assertFalse(AlertStatus.NEW.isClosed());
        assertFalse(AlertStatus.IN_PROGRESS.isClosed());
        assertTrue(AlertStatus.RESOLVED.isClosed());
        assertTrue(AlertStatus.FALSE_POSITIVE.isClosed());
    }

    @Test
    void aNewAlertStartsInTheQueue() {
        assertEquals(AlertStatus.NEW, new Alert().getStatus());
    }

    @Test
    void closingStampsTheCloseTimeAndReopeningClearsIt() {
        Alert alert = new Alert();

        alert.changeStatus(AlertStatus.IN_PROGRESS, T0);
        assertEquals(T0, alert.getStatusChangedAt());
        assertNull(alert.getResolvedAt());

        alert.changeStatus(AlertStatus.FALSE_POSITIVE, T0.plusSeconds(60));
        assertEquals(AlertStatus.FALSE_POSITIVE, alert.getStatus());
        assertEquals(T0.plusSeconds(60), alert.getResolvedAt());
        assertEquals(T0.plusSeconds(60), alert.getStatusChangedAt());

        alert.changeStatus(AlertStatus.IN_PROGRESS, T0.plusSeconds(120));
        assertNull(alert.getResolvedAt());
        assertEquals(T0.plusSeconds(120), alert.getStatusChangedAt());

        alert.changeStatus(AlertStatus.RESOLVED, T0.plusSeconds(180));
        assertEquals(T0.plusSeconds(180), alert.getResolvedAt());
    }

    @Test
    void aRefusedMoveChangesNothing() {
        Alert alert = new Alert();
        alert.changeStatus(AlertStatus.RESOLVED, T0);

        assertThrows(
                IllegalStateException.class,
                () -> alert.changeStatus(AlertStatus.FALSE_POSITIVE, T0.plusSeconds(60)));

        assertEquals(AlertStatus.RESOLVED, alert.getStatus());
        assertEquals(T0, alert.getResolvedAt());
        assertEquals(T0, alert.getStatusChangedAt());
    }
}
