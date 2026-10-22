package com.siem.analyzer.repo;

import com.siem.analyzer.domain.AttackTechnique;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.persistence.EntityManager;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

@ApplicationScoped
public class AttackTechniqueRepository implements PanacheRepositoryBase<AttackTechnique, String> {

    public List<AttackTechnique> findWithTactics(Collection<String> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        return find(
                        "select distinct t from AttackTechnique t left join fetch t.tactics"
                                + " where t.id in ?1",
                        ids)
                .list();
    }

    public List<AttackTechnique> listAllWithTactics() {
        return find("select distinct t from AttackTechnique t left join fetch t.tactics order by t.id")
                .list();
    }

    public Set<String> idsInTactics(Collection<String> tacticIds) {
        if (tacticIds.isEmpty()) {
            return Set.of();
        }
        return new TreeSet<>(
                getEntityManager()
                        .createQuery(
                                "select t.id from AttackTechnique t join t.tactics tactic"
                                        + " where tactic.id in :tactics",
                                String.class)
                        .setParameter("tactics", tacticIds)
                        .getResultList());
    }

    public void deleteDataset() {
        EntityManager entityManager = getEntityManager();
        entityManager.createNativeQuery("delete from attack_technique_tactic").executeUpdate();
        entityManager.createNativeQuery("delete from attack_technique").executeUpdate();
        entityManager.createNativeQuery("delete from attack_tactic").executeUpdate();
    }
}
