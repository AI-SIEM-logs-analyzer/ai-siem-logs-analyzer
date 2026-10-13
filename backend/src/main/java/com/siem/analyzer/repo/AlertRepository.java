package com.siem.analyzer.repo;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.Severity;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.panache.common.Page;
import io.quarkus.panache.common.Parameters;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.LockModeType;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Queries over {@link Alert}. */
@ApplicationScoped
public class AlertRepository implements PanacheRepositoryBase<Alert, Long> {

    /**
     * The rule, the triggering event and its source come with every alert read for display, so a
     * page of alerts is one query rather than one per row and association.
     */
    private static final String WITH_DETAILS =
            "from Alert a left join fetch a.rule join fetch a.logEvent e join fetch e.source";

    /**
     * Criteria for the alert listing. An empty set means "do not filter on this".
     *
     * @param severities keep only alerts of one of these severities
     * @param statuses keep only alerts in one of these statuses
     */
    public record Filter(Set<Severity> severities, Set<AlertStatus> statuses) {

        public Filter {
            severities = severities == null ? Set.of() : Set.copyOf(severities);
            statuses = statuses == null ? Set.of() : Set.copyOf(statuses);
        }
    }

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

    /**
     * One page of matching alerts, newest first, with their rule and triggering event loaded.
     *
     * <p>The id breaks ties between alerts raised in the same instant, so paging neither repeats
     * nor skips one.
     */
    public List<Alert> search(Filter filter, int page, int size) {
        Parameters parameters = new Parameters();
        String where = where(filter, parameters);
        return find(WITH_DETAILS + where + " order by a.raisedAt desc, a.id desc", parameters)
                .page(Page.of(page, size))
                .list();
    }

    /** Counts every alert the filter matches, ignoring paging. */
    public long count(Filter filter) {
        Parameters parameters = new Parameters();
        return find("from Alert a" + where(filter, parameters), parameters).count();
    }

    /** One alert with its rule and triggering event loaded, for its detail view. */
    public Optional<Alert> findWithDetails(Long id) {
        return find(WITH_DETAILS + " where a.id = :id", Parameters.with("id", id))
                .firstResultOptional();
    }

    /**
     * One alert, row-locked until the transaction ends, so two status changes to the same alert are
     * decided one after the other rather than both against the status they started from.
     */
    public Optional<Alert> findByIdForUpdate(Long id) {
        return findByIdOptional(id, LockModeType.PESSIMISTIC_WRITE);
    }

    /**
     * The {@code where} clause for {@code filter}, or nothing at all when it filters on nothing, so
     * the plain newest-first listing carries no predicate.
     */
    private static String where(Filter filter, Parameters parameters) {
        List<String> clauses = new ArrayList<>();
        if (!filter.severities().isEmpty()) {
            clauses.add("a.severity in :severities");
            parameters.and("severities", filter.severities());
        }
        if (!filter.statuses().isEmpty()) {
            clauses.add("a.status in :statuses");
            parameters.and("statuses", filter.statuses());
        }
        return clauses.isEmpty() ? "" : " where " + String.join(" and ", clauses);
    }
}
