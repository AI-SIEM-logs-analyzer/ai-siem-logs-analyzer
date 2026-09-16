package com.siem.analyzer.search;

import java.time.Instant;

/**
 * Where the previous page of results ended.
 *
 * <p>Paging by position rather than by offset: deep {@code from}/{@code size} paging makes the
 * engine sort every preceding hit again on every page, and a document indexed meanwhile shifts the
 * offsets underneath the caller. The pair is the sort key, so it is unique.
 *
 * @param occurredAt the last hit's event time
 * @param eventId the last hit's identifier, which breaks ties within one instant
 */
public record SearchCursor(Instant occurredAt, long eventId) {

    public SearchCursor {
        if (occurredAt == null) {
            throw new IllegalArgumentException("occurredAt is required");
        }
    }
}
