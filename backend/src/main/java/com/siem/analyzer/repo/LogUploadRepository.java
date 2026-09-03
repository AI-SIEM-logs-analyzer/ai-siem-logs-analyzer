package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

/** Queries over {@link LogUpload}. */
@ApplicationScoped
public class LogUploadRepository implements PanacheRepositoryBase<LogUpload, Long> {

    /** Finds an upload by its SHA-256 checksum to detect duplicate uploads. */
    public Optional<LogUpload> findByChecksum(String checksum) {
        return find("checksumSha256", checksum).firstResultOptional();
    }

    /** Lists uploads by status, newest first. */
    public List<LogUpload> listByStatus(LogUploadStatus status) {
        return find("status = ?1 order by createdAt desc", status).list();
    }

    /** Lists recent uploads up to a specified limit. */
    public List<LogUpload> listRecent(int limit) {
        return find("order by createdAt desc").page(0, limit).list();
    }
}
