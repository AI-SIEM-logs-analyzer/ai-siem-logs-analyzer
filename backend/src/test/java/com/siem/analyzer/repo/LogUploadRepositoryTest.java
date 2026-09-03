package com.siem.analyzer.repo;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.domain.LogSource;
import com.siem.analyzer.domain.LogSourceType;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import io.quarkus.test.TestTransaction;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

@QuarkusTest
class LogUploadRepositoryTest {

    @Inject LogUploadRepository uploadRepository;
    @Inject LogSourceRepository sourceRepository;

    private LogSource createSource(String name) {
        LogSource source = new LogSource();
        source.setName(name);
        source.setType(LogSourceType.SYSLOG);
        source.setHostname("host-" + name);
        source.setEnabled(true);
        sourceRepository.persist(source);
        return source;
    }

    private LogUpload createUpload(
            LogSource source, String fileName, String checksum, LogUploadStatus status) {
        LogUpload upload = new LogUpload();
        upload.setSource(source);
        upload.setFileName(fileName);
        upload.setContentType("text/plain");
        upload.setFileSize(1024L);
        upload.setChecksumSha256(checksum);
        upload.setStoragePath("/tmp/storage/" + fileName);
        upload.setStatus(status);
        upload.setUploadedBy("tester");
        upload.setCreatedAt(Instant.now());
        uploadRepository.persist(upload);
        return upload;
    }

    @Test
    @TestTransaction
    void persistsAndRetrievesLogUpload() {
        LogSource source = createSource("src-upload-" + UUID.randomUUID());
        String checksum = "sha256-" + UUID.randomUUID();
        LogUpload upload = createUpload(source, "app.log", checksum, LogUploadStatus.PENDING);

        assertNotNull(upload.getId());
        Optional<LogUpload> found = uploadRepository.findByIdOptional(upload.getId());
        assertTrue(found.isPresent());
        assertEquals("app.log", found.get().getFileName());
        assertEquals(source.getId(), found.get().getSource().getId());
        assertEquals(checksum, found.get().getChecksumSha256());
        assertEquals(LogUploadStatus.PENDING, found.get().getStatus());
    }

    @Test
    @TestTransaction
    void findsByChecksum() {
        String checksum = "unique-checksum-" + UUID.randomUUID();
        createUpload(null, "syslog.log", checksum, LogUploadStatus.PENDING);

        Optional<LogUpload> found = uploadRepository.findByChecksum(checksum);
        assertTrue(found.isPresent());
        assertEquals("syslog.log", found.get().getFileName());
    }

    @Test
    @TestTransaction
    void listsByStatusAndRecent() {
        String unique = UUID.randomUUID().toString();
        createUpload(null, "f1.log", "c1-" + unique, LogUploadStatus.PROCESSING);
        createUpload(null, "f2.log", "c2-" + unique, LogUploadStatus.INGESTED);

        List<LogUpload> processing = uploadRepository.listByStatus(LogUploadStatus.PROCESSING);
        assertTrue(processing.stream().anyMatch(u -> u.getFileName().equals("f1.log")));

        List<LogUpload> recent = uploadRepository.listRecent(10);
        assertTrue(recent.size() >= 2);
    }
}
