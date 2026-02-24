package com.github.tokoko.oidc;

import java.time.Instant;
import java.util.Optional;

public record TokenData(
    String accessToken,
    String tokenType,
    Instant expiresAt,
    Instant issuedAt,
    Optional<String> scope,
    Optional<String> refreshToken,
    Optional<String> idToken
) {}
