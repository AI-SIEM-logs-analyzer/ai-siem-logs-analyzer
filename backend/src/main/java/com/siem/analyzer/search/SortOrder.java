package com.siem.analyzer.search;

import java.util.Locale;

public enum SortOrder {
    ASC,

    DESC;

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

    public String engineValue() {
        return name().toLowerCase(Locale.ROOT);
    }
}
