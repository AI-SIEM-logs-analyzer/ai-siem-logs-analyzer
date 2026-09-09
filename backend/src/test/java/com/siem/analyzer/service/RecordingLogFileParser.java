package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Stands in for the real parser while the suite runs, recording what the consumer handed it.
 *
 * <p>A global alternative rather than a mock: the consumer resolves the same injection point it
 * resolves in production, and the suite can still make one upload fail on demand.
 */
@Alternative
@Priority(1)
@ApplicationScoped
public class RecordingLogFileParser implements LogFileParser {

    private final List<LogIngestEvent> received = new CopyOnWriteArrayList<>();
    private final Set<Long> failing = ConcurrentHashMap.newKeySet();

    @Override
    public void parse(LogIngestEvent event) {
        received.add(event);
        if (failing.contains(event.uploadId())) {
            throw new IllegalStateException("parser blew up on upload " + event.uploadId());
        }
    }

    /** Every event this parser was given, in the order the consumer delivered them. */
    public List<LogIngestEvent> received() {
        return List.copyOf(received);
    }

    /** True when the parser was handed the event for that upload. */
    public boolean sawUpload(Long uploadId) {
        return received.stream().anyMatch(event -> uploadId.equals(event.uploadId()));
    }

    /** Makes {@link #parse} throw for this upload. */
    public void failOn(Long uploadId) {
        failing.add(uploadId);
    }

    /** Forgets recorded events and failure instructions, so one test cannot leak into the next. */
    public void reset() {
        received.clear();
        failing.clear();
    }
}
