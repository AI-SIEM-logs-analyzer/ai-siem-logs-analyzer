package com.siem.analyzer.search;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.repo.LogEventIndexStateRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import jakarta.transaction.Status;
import jakarta.transaction.Synchronization;
import jakarta.transaction.TransactionSynchronizationRegistry;
import jakarta.transaction.Transactional;
import java.time.Instant;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * Moves events from PostgreSQL into the derived index and records that it did.
 *
 * <p>Two entry points, and the difference between them matters. {@link #drainBacklog(int)} is the
 * guarantee: it reads what PostgreSQL has and the index does not, so an event is eventually
 * searchable no matter what happened on the way in. {@link #indexAfterCommit(List)} is latency only
 * — it shortens the wait for events that have just landed, and dropping one of its writes costs
 * nothing, because the drain will pick the event up.
 *
 * <p>No method here propagates a failure of the engine. The index is derived; an ingestion path
 * that failed because search was unavailable would trade a stale read for lost data.
 */
@ApplicationScoped
public class EventIndexer {

    private static final Logger LOG = Logger.getLogger(EventIndexer.class);

    private final EventSearch search;
    private final LogEventIndexStateRepository indexState;
    private final TransactionSynchronizationRegistry transactionRegistry;
    private final EntityManager entityManager;

    @Inject
    public EventIndexer(
            EventSearch search,
            LogEventIndexStateRepository indexState,
            TransactionSynchronizationRegistry transactionRegistry,
            EntityManager entityManager) {
        this.search = search;
        this.indexState = indexState;
        this.transactionRegistry = transactionRegistry;
        this.entityManager = entityManager;
    }

    /**
     * Indexes these events and records them as indexed.
     *
     * @return how many reached the index; zero when the engine refused
     */
    @Transactional(Transactional.TxType.REQUIRED)
    public int indexNow(List<LogEvent> events) {
        if (events.isEmpty()) {
            return 0;
        }
        List<IndexableEvent> documents = events.stream().map(IndexableEvent::from).toList();
        try {
            search.index(documents);
        } catch (SearchUnavailableException e) {
            LOG.warnf(
                    e,
                    "Could not index %d events; they stay in the backlog and the next backfill"
                            + " run will retry them",
                    documents.size());
            return 0;
        }
        indexState.markIndexed(
                documents.stream().map(IndexableEvent::eventId).toList(), Instant.now());
        return documents.size();
    }

    /**
     * Indexes these events once the current transaction commits.
     *
     * <p>For the file parser to call as it persists a batch. Before the commit the rows are not
     * visible to anyone else, and a rollback would leave the index holding events PostgreSQL never
     * kept — the same ordering {@link com.siem.analyzer.service.LogIngestProducer} keeps for the
     * Kafka channel, and for the same reason.
     */
    public void indexAfterCommit(List<LogEvent> events) {
        if (events.isEmpty()) {
            return;
        }
        List<Long> ids = events.stream().map(LogEvent::getId).toList();
        int status = transactionRegistry.getTransactionStatus();
        if (status == Status.STATUS_NO_TRANSACTION) {
            indexByIds(ids);
            return;
        }
        if (status != Status.STATUS_ACTIVE) {
            LOG.debugf(
                    "Not scheduling an index write: transaction status is %d. The backfill job"
                            + " will pick these events up.",
                    status);
            return;
        }
        transactionRegistry.registerInterposedSynchronization(
                new Synchronization() {
                    @Override
                    public void beforeCompletion() {
                        // Nothing to do: the write belongs after the commit, not before it.
                    }

                    @Override
                    public void afterCompletion(int completionStatus) {
                        if (completionStatus != Status.STATUS_COMMITTED) {
                            LOG.debugf(
                                    "Transaction rolled back, not indexing %d events", ids.size());
                            return;
                        }
                        indexByIds(ids);
                    }
                });
    }

    /**
     * Indexes as much of the backlog as the limit allows.
     *
     * @return how many events reached the index
     */
    @Transactional(Transactional.TxType.REQUIRED)
    public int drainBacklog(int limit) {
        return indexNow(indexState.listUnindexed(limit));
    }

    /**
     * Re-reads the events by identifier, in a transaction of its own.
     *
     * <p>Called after the caller's transaction has completed, so its persistence context is gone
     * and the entities it held cannot be read from here.
     */
    @Transactional(Transactional.TxType.REQUIRES_NEW)
    void indexByIds(List<Long> ids) {
        try {
            indexNow(
                    entityManager
                            .createQuery(
                                    "select e from LogEvent e where e.id in :ids", LogEvent.class)
                            .setParameter("ids", ids)
                            .getResultList());
        } catch (RuntimeException e) {
            LOG.warnf(
                    e,
                    "Could not index %d events after commit; the backfill job will retry",
                    ids.size());
        }
    }
}
