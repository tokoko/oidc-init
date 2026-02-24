package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.ProfileNotFoundException;
import com.github.tokoko.oidc.exceptions.TokenNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class OidcClientTest {

    @TempDir
    Path tempDir;

    /** CliRunner that records calls instead of running the real binary. */
    static class NoOpCliRunner extends CliRunner {
        int initCallCount = 0;
        String lastProfile = null;

        @Override
        public void runInit(String profile) {
            initCallCount++;
            lastProfile = profile;
        }

        @Override
        public void runInit(String profile, long timeoutSeconds) {
            runInit(profile);
        }
    }

    private OidcClient createClient(Path tokensDir, Path profilesFile) {
        return new OidcClient(new TokenReader(tokensDir), new NoOpCliRunner(), profilesFile);
    }

    private OidcClient createClient(Path tokensDir, Path profilesFile, NoOpCliRunner cli) {
        return new OidcClient(new TokenReader(tokensDir), cli, profilesFile);
    }

    // -- resolveKey --

    @Test
    void explicitKeyReturned() {
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        assertEquals("my-key", client.resolveKey("my-key"));
    }

    @Test
    void fallsBackToDefaultProfile() throws IOException {
        Path profilesFile = tempDir.resolve("profiles.json");
        Files.writeString(profilesFile, "{\"_default\": \"my-default\"}");
        OidcClient client = createClient(tempDir, profilesFile);
        assertEquals("my-default", client.resolveKey(null));
    }

    @Test
    void throwsWithoutKeyOrDefault() {
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        assertThrows(ProfileNotFoundException.class, () -> client.resolveKey(null));
    }

    // -- getToken --

    @Test
    void returnsAccessToken() throws IOException {
        Map<String, String> data = TestHelpers.sampleTokenJson();
        TestHelpers.writeToken(tempDir, "test", data);
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        String token = client.getToken("test");
        assertEquals(data.get("access_token"), token);
    }

    @Test
    void triggersReauthOnExpired() throws IOException {
        TestHelpers.writeToken(tempDir, "exp", TestHelpers.expiredTokenJson());
        NoOpCliRunner cli = new NoOpCliRunner();
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"), cli);
        // After reauth the token file still has the expired data in tests
        client.getToken("exp");
        assertEquals(1, cli.initCallCount);
        assertEquals("exp", cli.lastProfile);
    }

    @Test
    void triggersReauthOnMissing() {
        NoOpCliRunner cli = new NoOpCliRunner();
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"), cli);
        // After reauth, token still won't exist in test, so expect TokenNotFoundException
        assertThrows(TokenNotFoundException.class, () -> client.getToken("missing"));
        assertEquals(1, cli.initCallCount);
        assertEquals("missing", cli.lastProfile);
    }

    // -- getTokens --

    @Test
    void returnsAllTokens() throws IOException {
        Map<String, String> data = TestHelpers.sampleTokenJson();
        TestHelpers.writeToken(tempDir, "test", data);
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        Map<String, String> tokens = client.getTokens("test");
        assertEquals(data.get("access_token"), tokens.get("access_token"));
        assertEquals("Bearer", tokens.get("token_type"));
        assertTrue(tokens.containsKey("refresh_token"));
        assertTrue(tokens.containsKey("id_token"));
    }

    @Test
    void omitsMissingOptionalTokens() throws IOException {
        String json = "{\"access_token\": \"tok\", \"token_type\": \"Bearer\", \"expires_at\": \"2099-01-01T00:00:00Z\"}";
        Files.writeString(tempDir.resolve("minimal.json"), json);
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        Map<String, String> tokens = client.getTokens("minimal");
        assertFalse(tokens.containsKey("refresh_token"));
        assertFalse(tokens.containsKey("id_token"));
    }

    // -- getTokenPath --

    @Test
    void returnsPath() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        String path = client.getTokenPath("test");
        assertTrue(path.endsWith("test.token"));
    }

    // -- listTokens --

    @Test
    void listsValidOnly() throws IOException {
        TestHelpers.writeToken(tempDir, "valid", TestHelpers.sampleTokenJson());
        TestHelpers.writeToken(tempDir, "expired", TestHelpers.expiredTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        List<String> keys = client.listTokens(false);
        assertTrue(keys.contains("valid"));
        assertFalse(keys.contains("expired"));
    }

    @Test
    void listsAllWithIncludeExpired() throws IOException {
        TestHelpers.writeToken(tempDir, "valid", TestHelpers.sampleTokenJson());
        TestHelpers.writeToken(tempDir, "expired", TestHelpers.expiredTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        List<String> keys = client.listTokens(true);
        assertTrue(keys.contains("valid"));
        assertTrue(keys.contains("expired"));
    }

    // -- isTokenValid --

    @Test
    void validTokenReturnsTrue() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        assertTrue(client.isTokenValid("test"));
    }

    @Test
    void expiredTokenReturnsFalse() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.expiredTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        assertFalse(client.isTokenValid("test"));
    }

    @Test
    void missingTokenReturnsFalse() {
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        assertFalse(client.isTokenValid("nonexistent"));
    }

    // -- purgeTokens --

    @Test
    void purgesTokens() throws IOException {
        TestHelpers.writeToken(tempDir, "a", TestHelpers.sampleTokenJson());
        TestHelpers.writeToken(tempDir, "b", TestHelpers.sampleTokenJson());
        OidcClient client = createClient(tempDir, tempDir.resolve("profiles.json"));
        int count = client.purgeTokens();
        assertEquals(2, count);
    }
}
