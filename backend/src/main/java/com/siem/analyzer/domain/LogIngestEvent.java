package com.siem.analyzer.domain;

import java.time.Instant;

public record LogIngestEvent(
        Long uploadId,
        Long sourceId,
        String sourceName,
        String sourceType,
        String fileName,
        String contentType,
        long fileSize,
        String checksum,
        String storagePath,
        String uploadedBy,
        Instant uploadedAt) {}
