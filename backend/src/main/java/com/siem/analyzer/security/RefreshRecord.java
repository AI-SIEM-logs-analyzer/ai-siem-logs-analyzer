package com.siem.analyzer.security;

/**
 * What Redis holds for one refresh token.
 *
 * <p>Stored as JSON under a string key rather than as a hash, because {@code GETDEL} — read and
 * delete in one command — is what guarantees that two concurrent refreshes cannot both succeed, and
 * it works on string values only.
 *
 * <p>{@code family} is constant across a chain of rotations: every token descended from one sign-in
 * shares it, which is what lets a replayed token identify the sessions to revoke.
 *
 * <p>The instant is kept as an epoch second rather than as an {@code Instant} so the JSON encoding
 * is a plain number and does not depend on how the application's object mapper is configured.
 */
public record RefreshRecord(long userId, String family, long issuedAtEpochSecond) {}
