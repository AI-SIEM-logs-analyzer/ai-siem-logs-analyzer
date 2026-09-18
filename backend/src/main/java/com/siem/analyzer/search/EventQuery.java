package com.siem.analyzer.search;

import com.siem.analyzer.domain.Severity;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * A validated search request.
 *
 * <p>Validated on construction rather than at the engine: every bound here is a limit on what one
 * caller can make the cluster do, and a limit enforced after the request has been built is a limit
 * that was not enforced. Built through {@link #builder()} because most of the fields are optional
 * and a constructor of twelve arguments reads as nothing at the call site.
 *
 * @param from earliest event time, inclusive; {@code null} for unbounded
 * @param to latest event time, exclusive; {@code null} for unbounded
 * @param sourceIds restrict to these sources; empty for all
 * @param severities restrict to these severities; empty for all
 * @param srcIps restrict to source addresses matching any of these; empty for all
 * @param statuses restrict to HTTP statuses within any of these ranges; empty for all
 * @param fullText ranked full-text over the message; {@code null} for none
 * @param substring literal substring of the raw line; {@code null} for none
 * @param size hits per page
 * @param order direction of the event-time sort
 * @param cursor where to resume; {@code null} for the first page; only valid with the same order
 * @param withFacets whether to compute aggregations, which cost a second pass
 */
public record EventQuery(
        Instant from,
        Instant to,
        Set<Long> sourceIds,
        Set<Severity> severities,
        Set<IpFilter> srcIps,
        Set<StatusFilter> statuses,
        String fullText,
        String substring,
        int size,
        SortOrder order,
        SearchCursor cursor,
        boolean withFacets) {

    /** Hits per page when the caller does not say. */
    public static final int DEFAULT_SIZE = 50;

    /** The largest page a caller may ask for. */
    public static final int MAX_SIZE = 1000;

    /**
     * The longest substring a caller may search for.
     *
     * <p>A denial-of-service bound. The {@code wildcard} field indexes substrings of length three
     * or less, so a longer pattern is answered by verifying candidates, and an unbounded one by
     * scanning. This constant is the sole, absolute bound the type enforces; there is no
     * corresponding configuration property.
     */
    public static final int MAX_SUBSTRING_LENGTH = 256;

    /**
     * The most values a caller may give one address or status filter.
     *
     * <p>Each value is a clause the engine evaluates per document, so the count is a cost bound
     * like the page size.
     */
    public static final int MAX_FILTER_VALUES = 50;

    public EventQuery {
        if (size < 1 || size > MAX_SIZE) {
            throw new IllegalArgumentException("size must be between 1 and " + MAX_SIZE);
        }
        if (from != null && to != null && !from.isBefore(to)) {
            throw new IllegalArgumentException("from must be before to");
        }
        fullText = blankToNull(fullText);
        substring = blankToNull(substring);
        if (substring != null && substring.length() > MAX_SUBSTRING_LENGTH) {
            throw new IllegalArgumentException(
                    "substring must be at most " + MAX_SUBSTRING_LENGTH + " characters");
        }
        sourceIds = unmodifiable(sourceIds);
        severities = unmodifiable(severities);
        srcIps = unmodifiable(srcIps);
        statuses = unmodifiable(statuses);
        if (srcIps.size() > MAX_FILTER_VALUES) {
            throw new IllegalArgumentException(
                    "at most " + MAX_FILTER_VALUES + " srcIp values are allowed");
        }
        if (statuses.size() > MAX_FILTER_VALUES) {
            throw new IllegalArgumentException(
                    "at most " + MAX_FILTER_VALUES + " status values are allowed");
        }
        if (order == null) {
            order = SortOrder.DESC;
        }
    }

    public static Builder builder() {
        return new Builder();
    }

    private static String blankToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static <T> Set<T> unmodifiable(Set<T> source) {
        return source == null ? Set.of() : Collections.unmodifiableSet(new LinkedHashSet<>(source));
    }

    /** Collects the optional parts of a query before validating them together. */
    public static final class Builder {

        private Instant from;
        private Instant to;
        private Set<Long> sourceIds = Set.of();
        private Set<Severity> severities = Set.of();
        private Set<IpFilter> srcIps = Set.of();
        private Set<StatusFilter> statuses = Set.of();
        private String fullText;
        private String substring;
        private int size = DEFAULT_SIZE;
        private SortOrder order = SortOrder.DESC;
        private SearchCursor cursor;
        private boolean withFacets;

        public Builder from(Instant value) {
            this.from = value;
            return this;
        }

        public Builder to(Instant value) {
            this.to = value;
            return this;
        }

        public Builder sourceIds(Set<Long> value) {
            this.sourceIds = value;
            return this;
        }

        public Builder severities(Set<Severity> value) {
            this.severities = value;
            return this;
        }

        public Builder srcIps(Set<IpFilter> value) {
            this.srcIps = value;
            return this;
        }

        public Builder statuses(Set<StatusFilter> value) {
            this.statuses = value;
            return this;
        }

        public Builder fullText(String value) {
            this.fullText = value;
            return this;
        }

        public Builder substring(String value) {
            this.substring = value;
            return this;
        }

        public Builder size(int value) {
            this.size = value;
            return this;
        }

        public Builder order(SortOrder value) {
            this.order = value;
            return this;
        }

        public Builder cursor(SearchCursor value) {
            this.cursor = value;
            return this;
        }

        public Builder withFacets(boolean value) {
            this.withFacets = value;
            return this;
        }

        public EventQuery build() {
            return new EventQuery(
                    from,
                    to,
                    sourceIds,
                    severities,
                    srcIps,
                    statuses,
                    fullText,
                    substring,
                    size,
                    order,
                    cursor,
                    withFacets);
        }
    }
}
