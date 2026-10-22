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

@ApplicationScoped
public class AlertRuleRepository implements PanacheRepositoryBase<AlertRule, Long> {

    public Optional<AlertRule> findByName(String name) {
        return find("name", name).firstResultOptional();
    }

    public List<AlertRule> listEnabled() {
        return find("enabled = true order by name").list();
    }

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
