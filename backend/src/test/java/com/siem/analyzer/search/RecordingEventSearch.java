package com.siem.analyzer.search;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
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
    private volatile boolean delegateToReal;

    @Inject OpenSearchEventSearch realSearch;

    @Override
    public void index(List<IndexableEvent> events) {
        if (failing) {
            throw new SearchUnavailableException("Refusing on purpose");
        }
        indexed.addAll(events);
        if (delegateToReal) {
            realSearch.index(events);
        }
    }

    @Override
    public SearchPage search(EventQuery query) {
        if (failing) {
            throw new SearchUnavailableException("Refusing on purpose");
        }
        if (delegateToReal) {
            return realSearch.search(query);
        }
        return SearchPage.empty();
    }

    @Override
    public boolean available() {
        if (delegateToReal) {
            return realSearch.available();
        }
        return !failing;
    }

    public List<IndexableEvent> indexed() {
        return List.copyOf(indexed);
    }

    public void failNextWrites(boolean value) {
        this.failing = value;
    }

    public void setDelegateToReal(boolean delegateToReal) {
        this.delegateToReal = delegateToReal;
    }

    public void reset() {
        indexed.clear();
        failing = false;
        delegateToReal = false;
    }
}
