package com.siem.analyzer.search;

import java.time.Instant;

public record SearchCursor(Instant occurredAt, long eventId) {

    public SearchCursor {
        if (occurredAt == null) {
            throw new IllegalArgumentException("occurredAt is required");
        }
    }
}
