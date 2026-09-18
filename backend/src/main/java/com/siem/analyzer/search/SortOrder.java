package com.siem.analyzer.search;

import java.util.Locale;

/**
 * Direction of the event-time sort.
 *
 * <p>Only the direction is selectable. The sort key stays {@code (occurredAt, eventId)} so that
 * {@link SearchCursor} keeps working unchanged; the cursor is only meaningful when handed back with
 * the same order that produced it.
 */
public enum SortOrder {
    /** Oldest first. */
    ASC,
    /** Newest first; the default. */
    DESC;

    /** Parses the {@code order} parameter, case-insensitively. Absent means {@link #DESC}. */
    public static SortOrder parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return DESC;
        }
        try {
            return valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("order must be asc or desc: " + raw, e);
        }
    }

    /** The value the engine's {@code sort} clause expects. */
    public String engineValue() {
        return name().toLowerCase(Locale.ROOT);
    }
}
