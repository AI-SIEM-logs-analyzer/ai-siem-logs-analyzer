package com.siem.analyzer.search;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * One HTTP status filter, as an inclusive range of codes.
 *
 * <p>An exact code and a whole class ({@code 5xx}) are both ranges, so the engine sees one shape of
 * clause whatever the caller typed.
 *
 * @param from lowest matching code, inclusive
 * @param to highest matching code, inclusive
 */
public record StatusFilter(int from, int to) {

    /** The lowest status code HTTP defines. */
    public static final int MIN_CODE = 100;

    /** The highest status code HTTP defines. */
    public static final int MAX_CODE = 599;

    private static final Pattern CODE = Pattern.compile("\\d{3}");
    private static final Pattern CLASS = Pattern.compile("[1-5]xx");

    public StatusFilter {
        if (from < MIN_CODE || to > MAX_CODE || from > to) {
            throw new IllegalArgumentException(
                    "status range must lie within " + MIN_CODE + "-" + MAX_CODE);
        }
    }

    /**
     * Parses one {@code status} parameter value: a code such as {@code 404} or a class such as
     * {@code 5xx}.
     */
    public static StatusFilter parse(String raw) {
        String candidate = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        if (CLASS.matcher(candidate).matches()) {
            int base = (candidate.charAt(0) - '0') * 100;
            return new StatusFilter(base, base + 99);
        }
        if (CODE.matcher(candidate).matches()) {
            int code = Integer.parseInt(candidate);
            if (code >= MIN_CODE && code <= MAX_CODE) {
                return new StatusFilter(code, code);
            }
        }
        throw new IllegalArgumentException(
                "status must be a code from "
                        + MIN_CODE
                        + " to "
                        + MAX_CODE
                        + " or a class such as 5xx: "
                        + raw);
    }
}
