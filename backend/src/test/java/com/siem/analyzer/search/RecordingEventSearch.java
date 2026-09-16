package com.siem.analyzer.search;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An {@link EventSearch} that records instead of indexing, and fails on demand.
 *
 * <p>Lets a test prove the bookkeeping around the index — what is written, in what order, and what
 * happens when the engine refuses — without asserting against a live cluster. {@link
 * #failNextWrites(boolean)} fails reads too, so the 503 path can be exercised from the REST layer
 * without stopping a container.
 */
@Mock
@ApplicationScoped
public class RecordingEventSearch implements EventSearch {

    private final List<IndexableEvent> indexed = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean failing;

    @Override
    public void index(List<IndexableEvent> events) {
        if (failing) {
            throw new SearchUnavailableException("Refusing on purpose");
        }
        indexed.addAll(events);
    }

    @Override
    public SearchPage search(EventQuery query) {
        if (failing) {
            throw new SearchUnavailableException("Refusing on purpose");
        }
        return SearchPage.empty();
    }

    @Override
    public boolean available() {
        return !failing;
    }

    public List<IndexableEvent> indexed() {
        return List.copyOf(indexed);
    }

    public void failNextWrites(boolean value) {
        this.failing = value;
    }

    public void reset() {
        indexed.clear();
        failing = false;
    }
}
