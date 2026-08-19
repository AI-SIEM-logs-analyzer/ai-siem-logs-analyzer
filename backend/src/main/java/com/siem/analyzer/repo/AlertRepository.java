package com.siem.analyzer.repo;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

/** Queries over {@link Alert}. */
@ApplicationScoped
public class AlertRepository implements PanacheRepositoryBase<Alert, Long> {

    /**
     * The triage queue for one status, newest first.
     *
     * <p>Matches the {@code (status, raised_at DESC)} index.
     */
    public List<Alert> listByStatus(AlertStatus status) {
        return find("status = ?1 order by raisedAt desc", status).list();
    }

    /** Every alert raised from one event — several rules can fire on the same line. */
    public List<Alert> listForLogEvent(Long logEventId) {
        return find("logEvent.id = ?1 order by raisedAt desc", logEventId).list();
    }
}
