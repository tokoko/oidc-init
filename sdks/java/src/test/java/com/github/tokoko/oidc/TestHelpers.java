package com.github.tokoko.oidc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

class TestHelpers {

    static Map<String, String> sampleTokenJson() {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Duration.ofHours(1));
        Map<String, String> data = new LinkedHashMap<>();
        data.put("access_token", "eyJhbGciOiJSUzI1NiJ9.sample_access");
        data.put("token_type", "Bearer");
        data.put("expires_at", expiresAt.toString());
        data.put("issued_at", now.toString());
        data.put("scope", "openid profile email");
        data.put("refresh_token", "eyJhbGciOiJSUzI1NiJ9.sample_refresh");
        data.put("id_token", "eyJhbGciOiJSUzI1NiJ9.sample_id");
        return data;
    }

    static Map<String, String> expiredTokenJson() {
        Instant now = Instant.now();
        Instant issuedAt = now.minus(Duration.ofHours(2));
        Instant expiresAt = now.minus(Duration.ofHours(1));
        Map<String, String> data = new LinkedHashMap<>();
        data.put("access_token", "eyJhbGciOiJSUzI1NiJ9.expired_access");
        data.put("token_type", "Bearer");
        data.put("expires_at", expiresAt.toString());
        data.put("issued_at", issuedAt.toString());
        data.put("scope", "openid profile email");
        return data;
    }

    static void writeToken(Path tokensDir, String key, Map<String, String> data) throws IOException {
        String sanitized = TokenReader.sanitizeKey(key);
        // Write JSON file
        StringBuilder json = new StringBuilder("{\n");
        int i = 0;
        for (var entry : data.entrySet()) {
            json.append("  \"").append(entry.getKey()).append("\": \"").append(entry.getValue()).append("\"");
            if (i < data.size() - 1) json.append(",");
            json.append("\n");
            i++;
        }
        json.append("}");
        Files.writeString(tokensDir.resolve(sanitized + ".json"), json.toString());

        // Write raw token file
        String accessToken = data.get("access_token");
        if (accessToken != null) {
            Files.writeString(tokensDir.resolve(sanitized + ".token"), accessToken);
        }
    }

    static String toJson(Map<String, String> data) {
        StringBuilder json = new StringBuilder("{\n");
        int i = 0;
        for (var entry : data.entrySet()) {
            json.append("  \"").append(entry.getKey()).append("\": \"").append(entry.getValue()).append("\"");
            if (i < data.size() - 1) json.append(",");
            json.append("\n");
            i++;
        }
        json.append("}");
        return json.toString();
    }
}
