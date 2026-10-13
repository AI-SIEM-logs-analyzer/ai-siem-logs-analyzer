package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AlertRule;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/** Queries over {@link AlertRule}. */
@ApplicationScoped
public class AlertRuleRepository implements PanacheRepositoryBase<AlertRule, Long> {

    /** Looks a rule up by its unique name. */
    public Optional<AlertRule> findByName(String name) {
        return find("name", name).firstResultOptional();
    }

    /** The rules a detection run should evaluate, ordered by name for a stable listing. */
    public List<AlertRule> listEnabled() {
        return find("enabled = true order by name").list();
    }

    /**
     * The technique IDs of each of {@code ruleIds}, in one query for a whole page of alerts. A rule
     * that maps no technique is absent from the map.
     */
    public Map<Long, Set<String>> techniqueIdsByRule(Collection<Long> ruleIds) {
        if (ruleIds.isEmpty()) {
            return Map.of();
        }
        Map<Long, Set<String>> byRule = new HashMap<>();
        for (Object[] row :
                getEntityManager()
                        .createQuery(
                                "select r.id, t from AlertRule r join r.techniqueIds t"
                                        + " where r.id in :ids",
                                Object[].class)
                        .setParameter("ids", ruleIds)
                        .getResultList()) {
            byRule.computeIfAbsent((Long) row[0], id -> new TreeSet<>()).add((String) row[1]);
        }
        return byRule;
    }

    /** Every technique an enabled rule maps to: what an alert raised from now on can name. */
    public Set<String> techniqueIdsOfEnabledRules() {
        return new TreeSet<>(
                getEntityManager()
                        .createQuery(
                                "select distinct t from AlertRule r join r.techniqueIds t"
                                        + " where r.enabled = true",
                                String.class)
                        .getResultList());
    }
}
