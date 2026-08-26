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

/**
 * Gives the seeded administrator a password, once.
 *
 * <p>{@code V2__users.sql} deliberately seeds an account whose hash matches no password, so that a
 * credential is not identical on every deployment that runs the migration. Something has to close
 * that gap, and a start-up setting is the smallest thing that can: an endpoint would be a permanent
 * door for a problem that exists once.
 *
 * <p>Idempotent, so {@code APP_AUTH_BOOTSTRAP_PASSWORD} can stay in the environment across restarts
 * without overwriting a password someone has since chosen.
 */
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

    /**
     * Sets the password on an account that has none.
     *
     * <p>Visible for the start-up path and for tests; the guard, not the caller, is what makes it
     * safe to call more than once.
     */
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
