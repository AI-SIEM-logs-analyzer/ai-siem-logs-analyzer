package com.siem.analyzer.search;

import java.util.List;

/**
 * One page of results.
 *
 * @param hits the page itself, newest event first
 * @param totalHits how many events matched in total; the engine's count, which is exact up to its
 *     own tracking limit and a lower bound beyond it
 * @param nextCursor where to resume, or {@code null} when this was the last page
 * @param facets counts across the whole match, empty when the query did not ask for them
 */
public record SearchPage(
        List<EventHit> hits, long totalHits, SearchCursor nextCursor, EventFacets facets) {

    public SearchPage {
        hits = hits == null ? List.of() : List.copyOf(hits);
        facets = facets == null ? EventFacets.none() : facets;
    }

    /** The answer to a query nothing matched. */
    public static SearchPage empty() {
        return new SearchPage(List.of(), 0L, null, EventFacets.none());
    }
}
