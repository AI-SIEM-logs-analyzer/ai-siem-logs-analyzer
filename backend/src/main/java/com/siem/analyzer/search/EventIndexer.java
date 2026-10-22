package com.siem.analyzer.search;

import com.siem.analyzer.domain.LogEvent;
import com.siem.analyzer.repo.LogEventIndexStateRepository;
import io.quarkus.narayana.jta.QuarkusTransaction;
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
                    public void beforeCompletion() {}

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

    @Transactional(Transactional.TxType.REQUIRED)
    public int drainBacklog(int limit) {
        return indexNow(indexState.listUnindexed(limit));
    }

    void indexByIds(List<Long> ids) {
        try {
            QuarkusTransaction.requiringNew()
                    .run(
                            () ->
                                    indexNow(
                                            entityManager
                                                    .createQuery(
                                                            "select e from LogEvent e where e.id"
                                                                    + " in :ids",
                                                            LogEvent.class)
                                                    .setParameter("ids", ids)
                                                    .getResultList()));
        } catch (RuntimeException e) {
            LOG.warnf(
                    e,
                    "Could not index %d events after commit; the backfill job will retry",
                    ids.size());
        }
    }
}
