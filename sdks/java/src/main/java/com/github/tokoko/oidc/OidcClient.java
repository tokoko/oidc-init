package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.ProfileNotFoundException;
import com.github.tokoko.oidc.exceptions.TokenNotFoundException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class OidcClient {

    private final TokenReader reader;
    private final CliRunner cliRunner;
    private final Path profilesFile;

    public OidcClient() {
        this(
            new TokenReader(),
            new CliRunner(),
            Path.of(System.getProperty("user.home"), ".oidc", "profiles.json")
        );
    }

    OidcClient(TokenReader reader, CliRunner cliRunner, Path profilesFile) {
        this.reader = reader;
        this.cliRunner = cliRunner;
        this.profilesFile = profilesFile;
    }

    String resolveKey(String storageKey) {
        if (storageKey != null && !storageKey.isEmpty()) {
            return storageKey;
        }

        if (Files.exists(profilesFile)) {
            try {
                String content = Files.readString(profilesFile);
                var defaultKey = JsonParser.extractString(content, "_default");
                if (defaultKey.isPresent() && !defaultKey.get().isEmpty()) {
                    return defaultKey.get();
                }
            } catch (IOException | RuntimeException ignored) {
            }
        }

        throw new ProfileNotFoundException(
            "No storage key provided and no default profile set. "
            + "Either specify a storage key or set a default profile with "
            + "'oidc profile set-default'."
        );
    }

    private void ensureValidToken(String finalKey) {
        try {
            if (reader.isExpired(finalKey)) {
                cliRunner.runInit(finalKey);
            }
        } catch (TokenNotFoundException e) {
            cliRunner.runInit(finalKey);
        }
    }

    public String getToken() {
        return getToken(null);
    }

    public String getToken(String storageKey) {
        String finalKey = resolveKey(storageKey);
        ensureValidToken(finalKey);
        TokenData data = reader.readTokenData(finalKey);
        return data.accessToken();
    }

    public Map<String, String> getTokens() {
        return getTokens(null);
    }

    public Map<String, String> getTokens(String storageKey) {
        String finalKey = resolveKey(storageKey);
        ensureValidToken(finalKey);
        TokenData data = reader.readTokenData(finalKey);

        Map<String, String> result = new LinkedHashMap<>();
        result.put("access_token", data.accessToken());
        result.put("token_type", data.tokenType());
        data.refreshToken().ifPresent(rt -> result.put("refresh_token", rt));
        data.idToken().ifPresent(id -> result.put("id_token", id));
        return result;
    }

    public String getTokenPath() {
        return getTokenPath(null);
    }

    public String getTokenPath(String storageKey) {
        String finalKey = resolveKey(storageKey);
        ensureValidToken(finalKey);
        return reader.tokenFilePath(finalKey);
    }

    public List<String> listTokens(boolean includeExpired) {
        List<String> allKeys = reader.listKeys();
        if (includeExpired) {
            return allKeys;
        }
        List<String> valid = new ArrayList<>();
        for (String key : allKeys) {
            try {
                if (!reader.isExpired(key)) {
                    valid.add(key);
                }
            } catch (RuntimeException ignored) {
            }
        }
        return valid;
    }

    public boolean isTokenValid(String storageKey) {
        try {
            return !reader.isExpired(storageKey);
        } catch (TokenNotFoundException e) {
            return false;
        }
    }

    public int purgeTokens() {
        return reader.purgeAll();
    }
}
