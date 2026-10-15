package com.siem.analyzer.repo;

import com.siem.analyzer.domain.Alert;
import com.siem.analyzer.domain.AlertStatus;
import com.siem.analyzer.domain.AttackType;
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
     * Which alerts an ATT&CK filter keeps: those whose rule maps a technique in {@code ids} or a
     * sub-technique of one of {@code bases}, and those without a rule whose model-assigned attack
     * type is in {@code attackTypes}. All three empty matches nothing: a filter on a tactic no
     * technique serves has no alert to show.
     *
     * @param ids technique IDs matched exactly
     * @param bases base technique IDs whose sub-techniques match too ({@code T1110} takes {@code
     *     T1110.001})
     * @param attackTypes the attack types of rule-less alerts that match
     */
    public record TechniqueCriterion(
            Set<String> ids, Set<String> bases, Set<AttackType> attackTypes) {

        public TechniqueCriterion {
            ids = Set.copyOf(ids);
            bases = Set.copyOf(bases);
            attackTypes = Set.copyOf(attackTypes);
        }
    }

    /**
     * Criteria for the alert listing. An empty set or a {@code null} criterion means "do not filter
     * on this".
     *
     * @param severities keep only alerts of one of these severities
     * @param statuses keep only alerts in one of these statuses
     * @param technique keep only alerts mapped to one of these ATT&CK techniques
     * @param tactic keep only alerts mapped to a technique under one of these ATT&CK tactics
     */
    public record Filter(
            Set<Severity> severities,
            Set<AlertStatus> statuses,
            TechniqueCriterion technique,
            TechniqueCriterion tactic) {

        public Filter {
            severities = severities == null ? Set.of() : Set.copyOf(severities);
            statuses = statuses == null ? Set.of() : Set.copyOf(statuses);
        }

        /** A filter on severity and status alone. */
        public Filter(Set<Severity> severities, Set<AlertStatus> statuses) {
            this(severities, statuses, null, null);
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
        if (filter.technique() != null) {
            clauses.add(techniqueClause(filter.technique(), "technique", parameters));
        }
        if (filter.tactic() != null) {
            clauses.add(techniqueClause(filter.tactic(), "tactic", parameters));
        }
        return clauses.isEmpty() ? "" : " where " + String.join(" and ", clauses);
    }

    /**
     * One ATT&CK criterion as HQL. The rule branch is a correlated {@code exists} over the rule's
     * technique IDs; {@code substring(t, 1, 5)} is a sub-technique's base ({@code T1110} of {@code
     * T1110.001}). Each part is left out when its set is empty, since {@code in ()} is not valid
     * SQL; with nothing left, {@code a.id is null}, which no row satisfies, keeps the query valid.
     */
    private static String techniqueClause(
            TechniqueCriterion criterion, String name, Parameters parameters) {
        List<String> ruleMatches = new ArrayList<>();
        if (!criterion.ids().isEmpty()) {
            ruleMatches.add("t in :" + name + "Ids");
            parameters.and(name + "Ids", criterion.ids());
        }
        if (!criterion.bases().isEmpty()) {
            ruleMatches.add("substring(t, 1, 5) in :" + name + "Bases");
            parameters.and(name + "Bases", criterion.bases());
        }
        List<String> branches = new ArrayList<>();
        if (!ruleMatches.isEmpty()) {
            branches.add(
                    "exists (select 1 from AlertRule r join r.techniqueIds t"
                            + " where r.id = a.rule.id and ("
                            + String.join(" or ", ruleMatches)
                            + "))");
        }
        if (!criterion.attackTypes().isEmpty()) {
            branches.add("(a.rule is null and a.aiAttackType in :" + name + "AttackTypes)");
            parameters.and(name + "AttackTypes", criterion.attackTypes());
        }
        return branches.isEmpty() ? "a.id is null" : "(" + String.join(" or ", branches) + ")";
    }
}
