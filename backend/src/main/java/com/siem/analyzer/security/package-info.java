/**
 * Token issuing, revocation and rate limiting.
 *
 * <p>Everything in this package is about credentials in flight: the access token and its claims,
 * the opaque refresh token, the deny-list that makes a logout immediate, and the counter that keeps
 * a sign-in endpoint from being a free oracle. Stored credentials — password hashing — stay in
 * {@code com.siem.analyzer.service}, which is the only place a plaintext password is handled.
 */
package com.siem.analyzer.security;
