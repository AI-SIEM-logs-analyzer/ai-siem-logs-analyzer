package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AttackTactic;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;

/** Queries over {@link AttackTactic}. */
@ApplicationScoped
public class AttackTacticRepository implements PanacheRepositoryBase<AttackTactic, String> {

    /** Every tactic, left to right as the Enterprise matrix lays them out. */
    public List<AttackTactic> listInMatrixOrder() {
        return list("order by ordinal, id");
    }
}
