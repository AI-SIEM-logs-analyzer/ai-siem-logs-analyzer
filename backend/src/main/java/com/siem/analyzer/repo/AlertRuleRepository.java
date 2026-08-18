package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AlertRule;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

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
}
