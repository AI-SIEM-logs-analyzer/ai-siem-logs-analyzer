package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogSource;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class LogSourceRepository implements PanacheRepositoryBase<LogSource, Long> {

    public Optional<LogSource> findByName(String name) {
        return find("name", name).firstResultOptional();
    }

    public List<LogSource> listEnabled() {
        return find("enabled = true order by name").list();
    }
}
