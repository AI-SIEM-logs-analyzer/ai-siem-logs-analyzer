package com.siem.analyzer.security;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.runtime.StartupEvent;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.eclipse.microprofile.jwt.Claims;

@ApplicationScoped
public class TokenService {

    private final AppConfig.Auth config;
    private final JWTParser parser;

    @Inject
    public TokenService(AppConfig config, JWTParser parser) {
        this.config = config.auth();
        this.parser = parser;
    }

    public record AccessToken(String value, String jti, Instant expiresAt) {}

    public AccessToken issue(User user) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(config.accessTtl());
        String jti = UUID.randomUUID().toString();
        Set<String> groups =
                user.getRoles().stream().map(Role::name).collect(Collectors.toUnmodifiableSet());

        String value =
                Jwt.issuer(config.issuer())
                        .subject(String.valueOf(user.getId()))
                        .upn(user.getUsername())
                        .groups(groups)
                        .claim(Claims.jti.name(), jti)
                        .issuedAt(now)
                        .expiresAt(expiresAt)
                        .sign();

        return new AccessToken(value, jti, expiresAt);
    }

    void verifyKeysOnStartup(@Observes StartupEvent event) {
        User probe = new User();
        probe.setUsername("startup-probe");
        try {
            parser.parse(issue(probe).value());
        } catch (ParseException e) {
            throw new IllegalStateException(
                    "JWT keys are missing or do not match: a token signed with"
                            + " smallrye.jwt.sign.key.location does not verify against"
                            + " mp.jwt.verify.publickey.location",
                    e);
        }
    }
}
