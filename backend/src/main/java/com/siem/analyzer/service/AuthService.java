package com.siem.analyzer.service;

import com.siem.analyzer.config.AppConfig;
import com.siem.analyzer.domain.AuthEventType;
import com.siem.analyzer.domain.User;
import com.siem.analyzer.security.LoginRateLimiter;
import com.siem.analyzer.security.RefreshTokenStore;
import com.siem.analyzer.security.TokenDenyList;
import com.siem.analyzer.security.TokenService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Sign-in, rotation and sign-out.
 *
 * <p>The only place that knows the order the pieces are used in: the rate limiter runs before the
 * password is checked, the audit trail is written whatever the outcome, and a refresh token is
 * exchanged exactly once. Everything it calls is testable on its own; this class is the sequence.
 */
@ApplicationScoped
public class AuthService {

    private final UserService users;
    private final TokenService tokens;
    private final RefreshTokenStore refreshTokens;
    private final TokenDenyList denyList;
    private final LoginRateLimiter rateLimiter;
    private final AuthEventRecorder audit;
    private final long accessTtlSeconds;

    @Inject
    public AuthService(
            UserService users,
            TokenService tokens,
            RefreshTokenStore refreshTokens,
            TokenDenyList denyList,
            LoginRateLimiter rateLimiter,
            AuthEventRecorder audit,
            AppConfig config) {
        this.users = users;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
        this.denyList = denyList;
        this.rateLimiter = rateLimiter;
        this.audit = audit;
        this.accessTtlSeconds = config.auth().accessTtl().toSeconds();
    }

    /** A pair of tokens as the API hands them out. */
    public record Tokens(String accessToken, String refreshToken, long expiresInSeconds) {}

    /**
     * Exchanges credentials for a token pair.
     *
     * @throws RateLimitedException before the password is checked, when this pair has failed too
     *     often — hashing a password is expensive by design, and an unthrottled endpoint would let
     *     anyone spend that cost
     * @throws InvalidCredentialsException for a wrong password, an unknown username or a disabled
     *     account, indistinguishably
     */
    public Tokens login(String username, String password, String clientIp) {
        Duration wait = rateLimiter.check(username, clientIp);
        if (wait != null) {
            audit.record(AuthEventType.RATE_LIMITED, username, null, clientIp, null);
            throw new RateLimitedException(wait);
        }

        Optional<User> authenticated = users.authenticate(username, password);
        if (authenticated.isEmpty()) {
            rateLimiter.recordFailure(username, clientIp);
            audit.record(AuthEventType.LOGIN_FAILURE, username, null, clientIp, null);
            throw new InvalidCredentialsException("invalid username or password");
        }

        User user = authenticated.get();
        rateLimiter.reset(username, clientIp);
        audit.record(AuthEventType.LOGIN_SUCCESS, username, user.getId(), clientIp, null);
        return issuePair(user, RefreshTokenStore.newFamily());
    }

    /**
     * Exchanges a refresh token for a new pair.
     *
     * <p>A token presented twice is treated as stolen: the first presentation was either the
     * legitimate holder or the thief, and there is no way to tell which, so every session of that
     * account goes.
     */
    public Tokens refresh(String refreshToken, String clientIp) {
        RefreshTokenStore.ConsumeResult consumed = refreshTokens.consume(refreshToken);

        switch (consumed.status()) {
            case ROTATED -> {
                User user =
                        users.findById(consumed.record().userId())
                                .filter(User::isEnabled)
                                .orElseThrow(
                                        () ->
                                                new InvalidCredentialsException(
                                                        "account is gone or disabled"));
                audit.record(
                        AuthEventType.REFRESH, user.getUsername(), user.getId(), clientIp, null);
                return issuePair(user, consumed.record().family());
            }
            case REUSED -> {
                long userId = consumed.record().userId();
                refreshTokens.revokeAllForUser(userId);
                audit.record(
                        AuthEventType.REFRESH_REUSE,
                        users.findById(userId).map(User::getUsername).orElse(null),
                        userId,
                        clientIp,
                        "family " + consumed.record().family() + " revoked after replay");
                throw new InvalidCredentialsException("refresh token has already been used");
            }
            default -> {
                audit.record(AuthEventType.REFRESH, null, null, clientIp, "unknown token");
                throw new InvalidCredentialsException("unknown refresh token");
            }
        }
    }

    /**
     * Ends a session.
     *
     * <p>Idempotent, and deliberately silent about what it found: a caller cannot learn whether a
     * token was live from the fact that it is now gone.
     */
    public void logout(
            String refreshToken,
            String jti,
            Instant accessExpiresAt,
            Long userId,
            String username,
            String clientIp) {
        if (refreshToken != null) {
            refreshTokens.revoke(refreshToken);
        }
        if (jti != null && accessExpiresAt != null) {
            denyList.deny(jti, Duration.between(Instant.now(), accessExpiresAt));
        }
        audit.record(AuthEventType.LOGOUT, username, userId, clientIp, null);
    }

    private Tokens issuePair(User user, String family) {
        TokenService.AccessToken access = tokens.issue(user);
        String refresh = refreshTokens.issue(user.getId(), family);
        return new Tokens(access.value(), refresh, accessTtlSeconds);
    }
}
