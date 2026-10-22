package com.siem.analyzer.search;

import java.util.List;

public record SearchPage(
        List<EventHit> hits, long totalHits, SearchCursor nextCursor, EventFacets facets) {

    public SearchPage {
        hits = hits == null ? List.of() : List.copyOf(hits);
        facets = facets == null ? EventFacets.none() : facets;
    }

    public static SearchPage empty() {
        return new SearchPage(List.of(), 0L, null, EventFacets.none());
    }
}
