package com.siem.analyzer.service;

import com.siem.analyzer.domain.LogIngestEvent;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Alternative;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

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

    public List<LogIngestEvent> received() {
        return List.copyOf(received);
    }

    public boolean sawUpload(Long uploadId) {
        return received.stream().anyMatch(event -> uploadId.equals(event.uploadId()));
    }

    public void failOn(Long uploadId) {
        failing.add(uploadId);
    }

    public void reset() {
        received.clear();
        failing.clear();
    }
}
