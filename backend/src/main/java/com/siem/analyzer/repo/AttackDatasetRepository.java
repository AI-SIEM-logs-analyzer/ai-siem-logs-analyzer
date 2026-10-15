package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AttackDataset;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;

/** The record of which ATT&CK release is loaded. */
@ApplicationScoped
public class AttackDatasetRepository implements PanacheRepositoryBase<AttackDataset, Short> {

    /** Key of the PostgreSQL advisory lock imports take; any constant no other code uses. */
    static final long IMPORT_LOCK = 0x4154_5426L;

    /** The loaded release; empty until the first import succeeds. */
    public Optional<AttackDataset> current() {
        return findByIdOptional(AttackDataset.ID);
    }

    /**
     * Holds the import lock until the transaction ends. Replicas starting together each run the
     * start-up import; the lock makes the second wait for the first rather than interleave its
     * deletes and inserts with it.
     */
    public void lockForImport() {
        getEntityManager()
                .createNativeQuery("select 1 from pg_advisory_xact_lock(" + IMPORT_LOCK + ")")
                .getResultList();
    }
}
