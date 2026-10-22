package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AttackDataset;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Optional;

@ApplicationScoped
public class AttackDatasetRepository implements PanacheRepositoryBase<AttackDataset, Short> {

    static final long IMPORT_LOCK = 0x4154_5426L;

    public Optional<AttackDataset> current() {
        return findByIdOptional(AttackDataset.ID);
    }

    public void lockForImport() {
        getEntityManager()
                .createNativeQuery("select 1 from pg_advisory_xact_lock(" + IMPORT_LOCK + ")")
                .getResultList();
    }
}
