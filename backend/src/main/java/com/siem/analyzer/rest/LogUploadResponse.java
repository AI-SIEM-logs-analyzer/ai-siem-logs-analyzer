package com.siem.analyzer.rest;

import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import java.time.Instant;

/** JSON payload returned when a log upload is processed or queried. */
public record LogUploadResponse(
        Long id,
        Long sourceId,
        String sourceName,
        String fileName,
        String contentType,
        long fileSize,
        String checksum,
        LogUploadStatus status,
        String storagePath,
        String uploadedBy,
        Instant createdAt) {

    public static LogUploadResponse from(LogUpload upload) {
        return new LogUploadResponse(
                upload.getId(),
                upload.getSource() != null ? upload.getSource().getId() : null,
                upload.getSource() != null ? upload.getSource().getName() : null,
                upload.getFileName(),
                upload.getContentType(),
                upload.getFileSize(),
                upload.getChecksumSha256(),
                upload.getStatus(),
                upload.getStoragePath(),
                upload.getUploadedBy(),
                upload.getCreatedAt());
    }
}
