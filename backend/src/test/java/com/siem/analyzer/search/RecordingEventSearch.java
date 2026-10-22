package com.siem.analyzer.search;

import io.quarkus.test.Mock;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Mock
@ApplicationScoped
public class RecordingEventSearch implements EventSearch {

    private final List<IndexableEvent> indexed = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean failing;
    private volatile boolean delegateToReal;
    private volatile EventQuery lastQuery;

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
        lastQuery = query;
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

    public EventQuery lastQuery() {
        return lastQuery;
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
        lastQuery = null;
    }
}
