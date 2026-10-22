package com.siem.analyzer.repo;

import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.hibernate.orm.panache.PanacheRepositoryBase;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import java.util.Optional;

@ApplicationScoped
public class UserRepository implements PanacheRepositoryBase<User, Long> {

    public Optional<User> findByUsername(String username) {
        return find("username", username).firstResultOptional();
    }

    public List<User> listEnabled() {
        return find("enabled = true order by username").list();
    }

    public List<User> listByRole(Role role) {
        return find(
                        "select distinct u from User u join u.roles r"
                                + " where r = ?1 order by u.username",
                        role)
                .list();
    }
}
