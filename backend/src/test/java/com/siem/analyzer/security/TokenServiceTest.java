package com.siem.analyzer.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.Role;
import com.siem.analyzer.domain.User;
import io.quarkus.test.junit.QuarkusTest;
import io.smallrye.jwt.auth.principal.JWTParser;
import io.smallrye.jwt.auth.principal.ParseException;
import io.smallrye.jwt.build.Jwt;
import jakarta.inject.Inject;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.junit.jupiter.api.Test;

@QuarkusTest
class TokenServiceTest {

    @Inject TokenService tokens;
    @Inject JWTParser parser;
    @Inject AppConfig config;

    private static User account() {
        User user = new User();
        user.setUsername("token.subject");
        user.setRoles(Set.of(Role.ANALYST, Role.VIEWER));
        return user;
    }

    @Test
    void issuesATokenCarryingTheAccountsIdentityAndRoles() throws ParseException {
        TokenService.AccessToken issued = tokens.issue(account());

        JsonWebToken parsed = parser.parse(issued.value());
        assertEquals(config.auth().issuer(), parsed.getIssuer());
        assertEquals("token.subject", parsed.getClaim(Claims.upn.name()));
        assertEquals(Set.of("ANALYST", "VIEWER"), parsed.getGroups());
        assertEquals(issued.jti(), parsed.getTokenID());
    }

    @Test
    void expiresAfterTheConfiguredAccessLifetime() throws ParseException {
        Instant before = Instant.now();

        TokenService.AccessToken issued = tokens.issue(account());

        JsonWebToken parsed = parser.parse(issued.value());
        Duration life = Duration.between(before, Instant.ofEpochSecond(parsed.getExpirationTime()));

        assertTrue(life.minus(config.auth().accessTtl()).abs().getSeconds() <= 1, life.toString());
        assertEquals(issued.expiresAt().getEpochSecond(), parsed.getExpirationTime());
    }

    @Test
    void givesEveryTokenItsOwnIdentifier() {
        assertNotEquals(tokens.issue(account()).jti(), tokens.issue(account()).jti());
    }

    @Test
    void rejectsATokenSignedWithAnotherKey() throws NoSuchAlgorithmException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        String forged =
                Jwt.issuer(config.auth().issuer())
                        .upn("token.subject")
                        .groups(Set.of("ADMIN"))
                        .jws()
                        .sign(generator.generateKeyPair().getPrivate());

        assertThrows(ParseException.class, () -> parser.parse(forged));
    }
}
