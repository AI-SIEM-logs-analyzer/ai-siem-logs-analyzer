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

/**
 * Mints access tokens.
 *
 * <p>The token is signed RS256 with the key at {@code smallrye.jwt.sign.key.location} and carries
 * only what an authorisation decision needs: who the account is and which roles it holds. Anything
 * that can change between issue and expiry — an e-mail address, whether the account is still
 * enabled — is deliberately absent, because a claim is a snapshot and a stale snapshot is worse
 * than a lookup.
 */
@ApplicationScoped
public class TokenService {

    private final AppConfig.Auth config;
    private final JWTParser parser;

    @Inject
    public TokenService(AppConfig config, JWTParser parser) {
        this.config = config.auth();
        this.parser = parser;
    }

    /**
     * An issued token, with the two facts the caller needs afterwards.
     *
     * <p>{@code jti} and {@code expiresAt} are what logout needs in order to deny the token for
     * exactly the rest of its life; digging them back out of the encoded form would mean parsing a
     * token this process just built.
     */
    public record AccessToken(String value, String jti, Instant expiresAt) {}

    /** Issues a token for an account. */
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

    /**
     * Proves at start-up that both keys load and agree.
     *
     * <p>MicroProfile resolves a key location lazily, so a missing or malformed key would otherwise
     * surface at the first sign-in — in production, as a failed request rather than a failed
     * deployment. Signing and verifying one throwaway token here moves that failure to boot, which
     * is the same contract {@code %prod} has for the datasource and the AI API key.
     */
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
