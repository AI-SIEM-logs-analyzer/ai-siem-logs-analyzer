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

/** Queries over {@link LogUpload}. */
@ApplicationScoped
public class LogUploadRepository implements PanacheRepositoryBase<LogUpload, Long> {

    /** Finds an upload by its SHA-256 checksum to detect duplicate uploads. */
    public Optional<LogUpload> findByChecksum(String checksum) {
        return find("checksumSha256", checksum).firstResultOptional();
    }

    /**
     * Criteria for the upload listing. A null field means "do not filter on this".
     *
     * @param status keep only uploads in this status
     * @param format keep only uploads whose content was detected as this format
     * @param uploadedBy the username recorded on the upload, matched exactly
     * @param from earliest {@code createdAt} to keep, inclusive
     * @param to {@code createdAt} to stop at, exclusive, so back-to-back ranges neither overlap nor
     *     drop a row that lands on the boundary
     */
    public record Filter(
            LogUploadStatus status,
            LogFormat format,
            String uploadedBy,
            Instant from,
            Instant to) {}

    /** Returns one page of matching uploads, newest first. */
    public List<LogUpload> search(Filter filter, int page, int size) {
        return applyFilter(filter).page(Page.of(page, size)).list();
    }

    /** Counts every upload the filter matches, ignoring paging. */
    public long count(Filter filter) {
        return applyFilter(filter).count();
    }

    /**
     * Builds the query from whichever fields the caller set.
     *
     * <p>Assembled as text rather than with a fixed {@code (:status IS NULL OR ...)} clause per
     * field: an absent filter then leaves no predicate at all, which is what lets the index on
     * {@code (status, created_at)} be used for the common "everything in one status" listing.
     */
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
