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

@ApplicationScoped
public class LogEventIndexStateRepository
        implements PanacheRepositoryBase<LogEventIndexState, Long> {

    @Inject EntityManager entityManager;

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

    public long countUnindexed() {
        return entityManager
                .createQuery(
                        "select count(e) from LogEvent e where e.id not in"
                                + " (select s.logEventId from LogEventIndexState s)",
                        Long.class)
                .getSingleResult();
    }

    private static final int MAX_ROWS_PER_STATEMENT = 1000;

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
