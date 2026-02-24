package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.StorageException;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class JsonParserTest {

    @Test
    void parseFlatSimpleObject() {
        String json = """
            {
              "access_token": "abc123",
              "token_type": "Bearer"
            }
            """;
        Map<String, String> result = JsonParser.parseFlat(json);
        assertEquals("abc123", result.get("access_token"));
        assertEquals("Bearer", result.get("token_type"));
        assertEquals(2, result.size());
    }

    @Test
    void parseFlatEmptyObject() {
        Map<String, String> result = JsonParser.parseFlat("{}");
        assertTrue(result.isEmpty());
    }

    @Test
    void parseFlatSkipsNonStringValues() {
        String json = """
            {
              "name": "test",
              "count": 42,
              "active": true,
              "data": null,
              "label": "hello"
            }
            """;
        Map<String, String> result = JsonParser.parseFlat(json);
        assertEquals("test", result.get("name"));
        assertEquals("hello", result.get("label"));
        assertEquals(2, result.size());
    }

    @Test
    void parseFlatSkipsNestedObjects() {
        String json = """
            {
              "_default": "my-profile",
              "my-profile": {
                "endpoint": "keycloak.example.com",
                "realm": "test"
              }
            }
            """;
        Map<String, String> result = JsonParser.parseFlat(json);
        assertEquals("my-profile", result.get("_default"));
        assertEquals(1, result.size());
    }

    @Test
    void parseFlatHandlesEscapedQuotes() {
        String json = "{\"key\": \"value with \\\"quotes\\\"\"}";
        Map<String, String> result = JsonParser.parseFlat(json);
        assertEquals("value with \"quotes\"", result.get("key"));
    }

    @Test
    void parseFlatThrowsOnInvalidJson() {
        assertThrows(StorageException.class, () -> JsonParser.parseFlat("not json"));
    }

    @Test
    void extractStringFindsKey() {
        String json = """
            {
              "_default": "my-profile",
              "other": {"nested": true}
            }
            """;
        Optional<String> result = JsonParser.extractString(json, "_default");
        assertTrue(result.isPresent());
        assertEquals("my-profile", result.get());
    }

    @Test
    void extractStringReturnsEmptyForMissingKey() {
        String json = """
            {"name": "test"}
            """;
        Optional<String> result = JsonParser.extractString(json, "_default");
        assertTrue(result.isEmpty());
    }

    @Test
    void extractStringReturnsEmptyForNonStringValue() {
        String json = """
            {"_default": {"nested": true}}
            """;
        Optional<String> result = JsonParser.extractString(json, "_default");
        assertTrue(result.isEmpty());
    }

    @Test
    void parseFlatFullTokenData() {
        Map<String, String> data = TestHelpers.sampleTokenJson();
        String json = TestHelpers.toJson(data);
        Map<String, String> result = JsonParser.parseFlat(json);
        assertEquals(data.get("access_token"), result.get("access_token"));
        assertEquals(data.get("token_type"), result.get("token_type"));
        assertEquals(data.get("expires_at"), result.get("expires_at"));
        assertEquals(data.get("refresh_token"), result.get("refresh_token"));
        assertEquals(data.get("id_token"), result.get("id_token"));
    }
}
