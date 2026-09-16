/**
 * The derived search index.
 *
 * <p>PostgreSQL is the system of record; everything here is a projection of it, built for reading
 * and rebuildable at any time. That is the property the rest of the application relies on: a
 * document that fails to reach the index is a stale read, never lost data.
 *
 * <p>{@link com.siem.analyzer.search.OpenSearchEventSearch} is the only class that speaks the
 * engine's wire protocol. Everything above this package works with {@link
 * com.siem.analyzer.search.EventQuery} and {@link com.siem.analyzer.search.SearchPage}.
 */
package com.siem.analyzer.search;
