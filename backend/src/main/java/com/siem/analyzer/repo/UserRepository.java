package com.siem.analyzer.repo;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

/** Queries over {@link User}. */
@ApplicationScoped
public class UserRepository implements PanacheRepositoryBase<User, Long> {

    /** Looks an account up by its unique username. */
    public Optional<User> findByUsername(String username) {
        return find("username", username).firstResultOptional();
    }

    /** Accounts that can currently sign in, ordered by username for a stable listing. */
    public List<User> listEnabled() {
        return find("enabled = true order by username").list();
    }

    /**
     * Accounts holding the given role.
     *
     * <p>Written as an explicit join over the role collection: {@code distinct} is required because
     * the join produces one row per matching role, and the eager fetch of {@code roles} would
     * otherwise return the same account several times.
     */
    public List<User> listByRole(Role role) {
        return find(
                        "select distinct u from User u join u.roles r"
                                + " where r = ?1 order by u.username",
                        role)
                .list();
    }
}
