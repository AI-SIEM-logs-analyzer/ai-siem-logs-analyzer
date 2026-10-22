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

@ApplicationScoped
public class AlertRepository implements PanacheRepositoryBase<Alert, Long> {

    private static final String WITH_DETAILS =
            "from Alert a left join fetch a.rule join fetch a.logEvent e join fetch e.source";

    public record TechniqueCriterion(
            Set<String> ids, Set<String> bases, Set<AttackType> attackTypes) {

        public TechniqueCriterion {
            ids = Set.copyOf(ids);
            bases = Set.copyOf(bases);
            attackTypes = Set.copyOf(attackTypes);
        }
    }

    public record Filter(
            Set<Severity> severities,
            Set<AlertStatus> statuses,
            TechniqueCriterion technique,
            TechniqueCriterion tactic) {

        public Filter {
            severities = severities == null ? Set.of() : Set.copyOf(severities);
            statuses = statuses == null ? Set.of() : Set.copyOf(statuses);
        }

        public Filter(Set<Severity> severities, Set<AlertStatus> statuses) {
            this(severities, statuses, null, null);
        }
    }

    public List<Alert> listByStatus(AlertStatus status) {
        return find("status = ?1 order by raisedAt desc", status).list();
    }

    public List<Alert> listForLogEvent(Long logEventId) {
        return find("logEvent.id = ?1 order by raisedAt desc", logEventId).list();
    }

    public List<Alert> search(Filter filter, int page, int size) {
        Parameters parameters = new Parameters();
        String where = where(filter, parameters);
        return find(WITH_DETAILS + where + " order by a.raisedAt desc, a.id desc", parameters)
                .page(Page.of(page, size))
                .list();
    }

    public long count(Filter filter) {
        Parameters parameters = new Parameters();
        return find("from Alert a" + where(filter, parameters), parameters).count();
    }

    public Optional<Alert> findWithDetails(Long id) {
        return find(WITH_DETAILS + " where a.id = :id", Parameters.with("id", id))
                .firstResultOptional();
    }

    public Optional<Alert> findByIdForUpdate(Long id) {
        return findByIdOptional(id, LockModeType.PESSIMISTIC_WRITE);
    }

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
