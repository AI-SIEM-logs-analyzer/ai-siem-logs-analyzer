package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.domain.LogEventIndexState;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.Collection;
import java.util.List;

/** Queries over {@link LogEventIndexState}, and the backlog they define. */
@ApplicationScoped
public class LogEventIndexStateRepository
        implements PanacheRepositoryBase<LogEventIndexState, Long> {

    @Inject EntityManager entityManager;

    /**
     * Events PostgreSQL holds and the index does not, oldest first.
     *
     * <p>An anti-join against this table. Ordering by id rather than by {@code occurred_at} keeps a
     * late-arriving batch from starving an older one, and makes a run's work deterministic.
     */
    public List<LogEvent> listUnindexed(int limit) {
        return entityManager
                .createQuery(
                        "select e from LogEvent e where e.id not in"
                                + " (select s.logEventId from LogEventIndexState s)"
                                + " order by e.id",
                        LogEvent.class)
                .setMaxResults(limit)
                .getResultList();
    }

    /** How far behind the index is. */
    public long countUnindexed() {
        return entityManager
                .createQuery(
                        "select count(e) from LogEvent e where e.id not in"
                                + " (select s.logEventId from LogEventIndexState s)",
                        Long.class)
                .getSingleResult();
    }

    /**
     * Caps how many rows go into a single {@code INSERT}. PostgreSQL allows at most 65535 bind
     * parameters per statement; at two parameters per row, 1000 rows per statement is a wide margin
     * under that ceiling.
     */
    private static final int MAX_ROWS_PER_STATEMENT = 1000;

    /**
     * Records that these events are in the index.
     *
     * <p>Written with {@code ON CONFLICT DO NOTHING}: a redelivered batch re-indexes the same
     * documents under the same identifiers, which is harmless, and must not fail here on a primary
     * key that is already present.
     *
     * <p>Issued as one multi-row {@code INSERT ... VALUES (?, ?), (?, ?), ...} per chunk rather
     * than one statement per id: Hibernate does not batch distinct native-query invocations, so a
     * loop of single-row inserts costs one round trip per id, turning a 1000-id backfill batch into
     * 1000 round trips. A single statement per chunk keeps that at one round trip per chunk. An
     * empty collection is a no-op — no statement is issued.
     */
    public void markIndexed(Collection<Long> eventIds, Instant at) {
        if (eventIds.isEmpty()) {
            return;
        }
        List<Long> ids = List.copyOf(eventIds);
        for (int offset = 0; offset < ids.size(); offset += MAX_ROWS_PER_STATEMENT) {
            List<Long> chunk =
                    ids.subList(offset, Math.min(offset + MAX_ROWS_PER_STATEMENT, ids.size()));
            insertChunk(chunk, at);
        }
    }

    /** Inserts one chunk of ids as a single multi-row statement. */
    private void insertChunk(List<Long> chunk, Instant at) {
        StringBuilder sql =
                new StringBuilder(
                        "INSERT INTO log_event_index_state (log_event_id, indexed_at) VALUES ");
        for (int i = 0; i < chunk.size(); i++) {
            if (i > 0) {
                sql.append(", ");
            }
            sql.append('(')
                    .append('?')
                    .append(i * 2 + 1)
                    .append(", ?")
                    .append(i * 2 + 2)
                    .append(')');
        }
        sql.append(" ON CONFLICT (log_event_id) DO NOTHING");

        var query = entityManager.createNativeQuery(sql.toString());
        for (int i = 0; i < chunk.size(); i++) {
            query.setParameter(i * 2 + 1, chunk.get(i));
            query.setParameter(i * 2 + 2, at);
        }
        query.executeUpdate();
    }
}
