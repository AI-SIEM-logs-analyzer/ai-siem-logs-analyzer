package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogEvent;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class LogEventRepository implements PanacheRepositoryBase<LogEvent, Long> {

    public Optional<LogEvent> findByExternalId(String externalId) {
        return find("externalId", externalId).firstResultOptional();
    }

    public List<LogEvent> listForSourceBetween(
            Long sourceId, Instant fromInclusive, Instant toExclusive) {
        return find(
                        "source.id = ?1 and occurredAt >= ?2 and occurredAt < ?3"
                                + " order by occurredAt desc",
                        sourceId,
                        fromInclusive,
                        toExclusive)
                .list();
    }

    public List<LogEvent> listForSourceWithin(
            Long sourceId, Instant fromInclusive, Instant toInclusive, int limit) {
        return find(
                        "source.id = ?1 and occurredAt >= ?2 and occurredAt <= ?3"
                                + " order by occurredAt desc, id desc",
                        sourceId,
                        fromInclusive,
                        toInclusive)
                .range(0, limit - 1)
                .list();
    }
}
