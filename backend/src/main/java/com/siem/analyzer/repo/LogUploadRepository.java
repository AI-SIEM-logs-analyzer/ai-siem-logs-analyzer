package com.siem.analyzer.repo;

import com.siem.analyzer.domain.LogFormat;
import com.siem.analyzer.domain.LogUpload;
import com.siem.analyzer.domain.LogUploadStatus;
import io.quarkus.hibernate.orm.panache.PanacheQuery;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import io.quarkus.panache.common.Page;
import io.quarkus.panache.common.Parameters;
import io.quarkus.panache.common.Sort;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class LogUploadRepository implements PanacheRepositoryBase<LogUpload, Long> {

    public Optional<LogUpload> findByChecksum(String checksum) {
        return find("checksumSha256", checksum).firstResultOptional();
    }

    public record Filter(
            LogUploadStatus status,
            LogFormat format,
            String uploadedBy,
            Instant from,
            Instant to) {}

    public List<LogUpload> search(Filter filter, int page, int size) {
        return applyFilter(filter).page(Page.of(page, size)).list();
    }

    public long count(Filter filter) {
        return applyFilter(filter).count();
    }

    private PanacheQuery<LogUpload> applyFilter(Filter filter) {
        List<String> clauses = new ArrayList<>();
        Parameters parameters = new Parameters();

        if (filter.status() != null) {
            clauses.add("status = :status");
            parameters.and("status", filter.status());
        }
        if (filter.format() != null) {
            clauses.add("detectedFormat = :format");
            parameters.and("format", filter.format());
        }
        if (filter.uploadedBy() != null && !filter.uploadedBy().isBlank()) {
            clauses.add("uploadedBy = :uploadedBy");
            parameters.and("uploadedBy", filter.uploadedBy());
        }
        if (filter.from() != null) {
            clauses.add("createdAt >= :from");
            parameters.and("from", filter.from());
        }
        if (filter.to() != null) {
            clauses.add("createdAt < :to");
            parameters.and("to", filter.to());
        }

        Sort newestFirst = Sort.by("createdAt", Sort.Direction.Descending);
        if (clauses.isEmpty()) {
            return findAll(newestFirst);
        }
        return find(String.join(" and ", clauses), newestFirst, parameters);
    }
}
