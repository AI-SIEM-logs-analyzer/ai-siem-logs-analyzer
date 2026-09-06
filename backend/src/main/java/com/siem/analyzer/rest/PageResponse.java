package com.siem.analyzer.rest;

import java.util.List;

/**
 * One page of results plus the size of the whole match.
 *
 * <p>An envelope rather than a bare array: without {@code total} a client cannot tell a short page
 * from the last page, and would have to keep requesting pages until one comes back empty.
 *
 * @param items the rows on this page, in the listing's own order
 * @param page zero-based index of this page
 * @param size the page size actually applied, which may be smaller than the one requested
 * @param total rows matching the filter across every page
 */
public record PageResponse<T>(List<T> items, int page, int size, long total) {}
