package com.siem.analyzer.search;

import java.util.List;

/**
 * The seam between the application and whatever engine answers searches.
 *
 * <p>Everything above this interface works in domain terms. The one implementation that speaks a
 * wire protocol is {@link OpenSearchEventSearch}; tests substitute their own.
 */
public interface EventSearch {

    /**
     * Writes these events to the index, replacing any document already stored under the same event
     * identifier.
     *
     * <p>Idempotent by construction, because the document identifier is the event's. A batch
     * redelivered by the broker overwrites rather than duplicating.
     *
     * @throws SearchUnavailableException the engine could not be reached or refused the batch
     */
    void index(List<IndexableEvent> events);

    /**
     * Answers one query.
     *
     * @throws SearchUnavailableException the engine could not be reached or refused the query
     */
    SearchPage search(EventQuery query);

    /** Whether the engine answered a ping. Never throws; a failure is reported as {@code false}. */
    boolean available();
}
