package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogSource;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

/** Queries over {@link LogSource}. */
@ApplicationScoped
public class LogSourceRepository implements PanacheRepositoryBase<LogSource, Long> {

    /** Looks a source up by its unique name. */
    public Optional<LogSource> findByName(String name) {
        return find("name", name).firstResultOptional();
    }

    /** Sources that are currently collecting, ordered by name for a stable listing. */
    public List<LogSource> listEnabled() {
        return find("enabled = true order by name").list();
    }
}
