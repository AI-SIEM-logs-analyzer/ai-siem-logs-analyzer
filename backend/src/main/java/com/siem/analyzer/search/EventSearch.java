package com.siem.analyzer.search;

import java.util.List;

public interface EventSearch {

    void index(List<IndexableEvent> events);

    SearchPage search(EventQuery query);

    boolean available();
}
