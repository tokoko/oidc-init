package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.StorageException;
import com.github.tokoko.oidc.exceptions.TokenNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class TokenReaderTest {

    @TempDir
    Path tempDir;

    // -- readTokenData --

    @Test
    void readTokenDataReadsValidToken() throws IOException {
        Map<String, String> data = TestHelpers.sampleTokenJson();
        TestHelpers.writeToken(tempDir, "test", data);
        TokenReader reader = new TokenReader(tempDir);

        TokenData token = reader.readTokenData("test");
        assertEquals(data.get("access_token"), token.accessToken());
        assertEquals("Bearer", token.tokenType());
        assertTrue(token.refreshToken().isPresent());
        assertTrue(token.idToken().isPresent());
    }

    @Test
    void readTokenDataThrowsOnMissing() {
        TokenReader reader = new TokenReader(tempDir);
        assertThrows(TokenNotFoundException.class, () -> reader.readTokenData("nonexistent"));
    }

    @Test
    void readTokenDataThrowsOnInvalidJson() throws IOException {
        Files.writeString(tempDir.resolve("bad.json"), "not json");
        TokenReader reader = new TokenReader(tempDir);
        StorageException ex = assertThrows(StorageException.class, () -> reader.readTokenData("bad"));
        assertTrue(ex.getMessage().contains("Invalid JSON"));
    }

    @Test
    void readTokenDataThrowsOnMissingAccessToken() throws IOException {
        Files.writeString(tempDir.resolve("notoken.json"), "{\"token_type\": \"Bearer\"}");
        TokenReader reader = new TokenReader(tempDir);
        StorageException ex = assertThrows(StorageException.class, () -> reader.readTokenData("notoken"));
        assertTrue(ex.getMessage().contains("Invalid token file"));
    }

    // -- isExpired --

    @Test
    void validTokenNotExpired() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        assertFalse(reader.isExpired("test"));
    }

    @Test
    void expiredToken() throws IOException {
        TestHelpers.writeToken(tempDir, "expired", TestHelpers.expiredTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        assertTrue(reader.isExpired("expired"));
    }

    @Test
    void missingExpiresAtTreatedAsExpired() throws IOException {
        Files.writeString(tempDir.resolve("no-expiry.json"),
            "{\"access_token\": \"tok\", \"token_type\": \"Bearer\"}");
        TokenReader reader = new TokenReader(tempDir);
        assertTrue(reader.isExpired("no-expiry"));
    }

    @Test
    void isExpiredThrowsOnMissingKey() {
        TokenReader reader = new TokenReader(tempDir);
        assertThrows(TokenNotFoundException.class, () -> reader.isExpired("nonexistent"));
    }

    // -- tokenFilePath --

    @Test
    void returnsTokenPath() {
        TokenReader reader = new TokenReader(tempDir);
        String path = reader.tokenFilePath("my-key");
        assertTrue(path.endsWith("my-key.token"));
    }

    @Test
    void sanitizesKeyInPath() {
        TokenReader reader = new TokenReader(tempDir);
        String path = reader.tokenFilePath("host:8080/realm");
        String fileName = Path.of(path).getFileName().toString();
        assertFalse(fileName.contains(":"));
        assertFalse(fileName.contains("/"));
    }

    // -- listKeys --

    @Test
    void listsKeys() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        List<String> keys = reader.listKeys();
        assertTrue(keys.contains("test"));
    }

    @Test
    void deduplicatesJsonAndToken() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        List<String> keys = reader.listKeys();
        assertEquals(1, keys.stream().filter(k -> k.equals("test")).count());
    }

    @Test
    void emptyDir() {
        TokenReader reader = new TokenReader(tempDir);
        assertEquals(List.of(), reader.listKeys());
    }

    @Test
    void nonexistentDir() {
        TokenReader reader = new TokenReader(tempDir.resolve("does-not-exist"));
        assertEquals(List.of(), reader.listKeys());
    }

    @Test
    void multipleKeys() throws IOException {
        TestHelpers.writeToken(tempDir, "alpha", TestHelpers.sampleTokenJson());
        TestHelpers.writeToken(tempDir, "beta", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        List<String> keys = reader.listKeys();
        List<String> sorted = keys.stream().sorted().toList();
        assertEquals(List.of("alpha", "beta"), sorted);
    }

    // -- deleteTokenFiles --

    @Test
    void deletesBothFiles() throws IOException {
        TestHelpers.writeToken(tempDir, "test", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        reader.deleteTokenFiles("test");
        assertFalse(Files.exists(tempDir.resolve("test.json")));
        assertFalse(Files.exists(tempDir.resolve("test.token")));
    }

    @Test
    void deleteThrowsOnMissing() {
        TokenReader reader = new TokenReader(tempDir);
        assertThrows(TokenNotFoundException.class, () -> reader.deleteTokenFiles("nonexistent"));
    }

    // -- purgeAll --

    @Test
    void purgesAll() throws IOException {
        TestHelpers.writeToken(tempDir, "a", TestHelpers.sampleTokenJson());
        TestHelpers.writeToken(tempDir, "b", TestHelpers.sampleTokenJson());
        TokenReader reader = new TokenReader(tempDir);
        int count = reader.purgeAll();
        assertEquals(2, count);
        assertEquals(List.of(), reader.listKeys());
    }

    @Test
    void purgeEmptyDir() {
        TokenReader reader = new TokenReader(tempDir);
        assertEquals(0, reader.purgeAll());
    }

    @Test
    void purgeNonexistentDir() {
        TokenReader reader = new TokenReader(tempDir.resolve("nope"));
        assertEquals(0, reader.purgeAll());
    }

    // -- sanitizeKey --

    @Test
    void sanitizeKeyReplacesSpecialChars() {
        assertEquals("host_8080_realm", TokenReader.sanitizeKey("host:8080/realm"));
    }

    @Test
    void sanitizeKeyPreservesValidChars() {
        assertEquals("my-key.name", TokenReader.sanitizeKey("my-key.name"));
    }
}
