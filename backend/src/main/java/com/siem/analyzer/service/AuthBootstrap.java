package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import java.util.List;
import java.util.Optional;
import org.jboss.logging.Logger;

@ApplicationScoped
public class AuthBootstrap {

    private static final Logger LOG = Logger.getLogger(AuthBootstrap.class);

    private final UserService users;
    private final PasswordService passwords;
    private final Optional<String> configuredPassword;

    @Inject
    public AuthBootstrap(UserService users, PasswordService passwords, AppConfig config) {
        this.users = users;
        this.passwords = passwords;
        this.configuredPassword = config.auth().bootstrapPassword();
    }

    @Transactional
    void onStartup(@Observes StartupEvent event) {
        List<User> administrators = users.listByRole(Role.ADMIN);
        configuredPassword.ifPresent(
                password -> administrators.forEach(admin -> applyTo(admin, password)));

        boolean anyUsable =
                users.listByRole(Role.ADMIN).stream()
                        .anyMatch(
                                admin ->
                                        admin.isEnabled()
                                                && !passwords.isLocked(admin.getPasswordHash()));
        if (!anyUsable) {
            LOG.warn(
                    "no enabled administrator has a usable password: this deployment cannot be"
                            + " signed into. Set APP_AUTH_BOOTSTRAP_PASSWORD and restart.");
        }
    }

    @Transactional
    void applyTo(User admin, String password) {
        if (!passwords.isLocked(admin.getPasswordHash())) {
            return;
        }
        admin.setPasswordHash(passwords.hash(password));
        LOG.warnf(
                "set the bootstrap password on administrator '%s'; change it after the first"
                        + " sign-in",
                admin.getUsername());
    }
}
