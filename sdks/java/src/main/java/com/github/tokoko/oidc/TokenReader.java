package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.StorageException;
import com.github.tokoko.oidc.exceptions.TokenNotFoundException;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public class TokenReader {

    private final Path tokensDir;

    public TokenReader() {
        this(Path.of(System.getProperty("user.home"), ".oidc", "cache", "tokens"));
    }

    public TokenReader(Path tokensDir) {
        this.tokensDir = tokensDir;
    }

    static String sanitizeKey(String key) {
        return key.replaceAll("[^\\w\\-.]", "_");
    }

    Path jsonPath(String key) {
        return tokensDir.resolve(sanitizeKey(key) + ".json");
    }

    Path tokenPath(String key) {
        return tokensDir.resolve(sanitizeKey(key) + ".token");
    }

    public TokenData readTokenData(String storageKey) {
        Path jp = jsonPath(storageKey);
        if (!Files.exists(jp)) {
            throw new TokenNotFoundException("No tokens found for '" + storageKey + "'");
        }
        try {
            String content = Files.readString(jp);
            Map<String, String> data = JsonParser.parseFlat(content);

            String accessToken = data.get("access_token");
            if (accessToken == null || accessToken.isEmpty()) {
                throw new StorageException("Invalid token file for '" + storageKey + "'");
            }

            String tokenType = data.getOrDefault("token_type", "Bearer");
            Instant expiresAt = parseTimestamp(data.get("expires_at"));
            Instant issuedAt = parseTimestamp(data.get("issued_at"));

            return new TokenData(
                accessToken,
                tokenType,
                expiresAt,
                issuedAt,
                Optional.ofNullable(emptyToNull(data.get("scope"))),
                Optional.ofNullable(emptyToNull(data.get("refresh_token"))),
                Optional.ofNullable(emptyToNull(data.get("id_token")))
            );
        } catch (StorageException e) {
            throw e;
        } catch (IOException e) {
            throw new StorageException("Failed to read token file for '" + storageKey + "': " + e.getMessage(), e);
        }
    }

    public boolean isExpired(String storageKey) {
        TokenData data = readTokenData(storageKey);
        if (data.expiresAt() == null) {
            return true;
        }
        return !Instant.now().isBefore(data.expiresAt());
    }

    public String tokenFilePath(String storageKey) {
        return tokenPath(storageKey).toString();
    }

    public List<String> listKeys() {
        if (!Files.exists(tokensDir) || !Files.isDirectory(tokensDir)) {
            return List.of();
        }
        Set<String> seen = new LinkedHashSet<>();
        List<Path> entries = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tokensDir)) {
            for (Path entry : stream) {
                entries.add(entry);
            }
        } catch (IOException e) {
            return List.of();
        }
        entries.sort((a, b) -> a.getFileName().toString().compareTo(b.getFileName().toString()));
        for (Path entry : entries) {
            if (Files.isDirectory(entry)) continue;
            String name = entry.getFileName().toString();
            if (name.endsWith(".json") || name.endsWith(".token")) {
                String stem = name.substring(0, name.lastIndexOf('.'));
                seen.add(stem);
            }
        }
        return new ArrayList<>(seen);
    }

    public void deleteTokenFiles(String storageKey) {
        Path jp = jsonPath(storageKey);
        Path tp = tokenPath(storageKey);
        boolean found = false;
        try {
            if (Files.deleteIfExists(jp)) found = true;
            if (Files.deleteIfExists(tp)) found = true;
        } catch (IOException e) {
            throw new StorageException("Failed to delete token files for '" + storageKey + "'", e);
        }
        if (!found) {
            throw new TokenNotFoundException("No tokens found for '" + storageKey + "'");
        }
    }

    public int purgeAll() {
        if (!Files.exists(tokensDir) || !Files.isDirectory(tokensDir)) {
            return 0;
        }
        int count = 0;
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(tokensDir)) {
            for (Path entry : stream) {
                if (Files.isDirectory(entry)) continue;
                if (entry.getFileName().toString().endsWith(".json")) {
                    count++;
                }
                Files.delete(entry);
            }
        } catch (IOException e) {
            throw new StorageException("Failed to purge tokens: " + e.getMessage(), e);
        }
        return count;
    }

    private static Instant parseTimestamp(String value) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    private static String emptyToNull(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }
}
