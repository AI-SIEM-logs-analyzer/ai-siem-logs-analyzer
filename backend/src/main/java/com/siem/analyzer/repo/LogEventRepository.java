package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogEvent;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/** Queries over {@link LogEvent}. */
@ApplicationScoped
public class LogEventRepository implements PanacheRepositoryBase<LogEvent, Long> {

    /** Finds the event an upstream record already produced, so a replay can be discarded. */
    public Optional<LogEvent> findByExternalId(String externalId) {
        return find("externalId", externalId).firstResultOptional();
    }

    /**
     * Events of one source in a half-open interval, newest first.
     *
     * <p>The upper bound is exclusive so that consecutive windows neither overlap nor leave a gap.
     * Matches the {@code (source_id, occurred_at DESC)} index.
     */
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

    /**
     * The newest {@code limit} events of one source in a closed interval, newest first.
     *
     * <p>For the context of an alert, whose window ends on the newest event it counted, so the
     * upper bound is inclusive here. Matches the {@code (source_id, occurred_at DESC)} index.
     */
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
