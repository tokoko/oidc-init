package com.github.tokoko.oidc;

import com.github.tokoko.oidc.exceptions.StorageException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Minimal JSON parser for flat string-keyed objects. Package-private.
 * Only handles the well-formed JSON written by the Go CLI binary.
 */
class JsonParser {

    private record ParsedString(String value, int endPos) {}

    /**
     * Parse a flat JSON object (all values are strings) into a Map.
     * Skips values that are not quoted strings (objects, arrays, etc.).
     */
    static Map<String, String> parseFlat(String json) {
        Map<String, String> result = new LinkedHashMap<>();
        int len = json.length();
        int i = skipWhitespace(json, 0, len);

        if (i >= len || json.charAt(i) != '{') {
            throw new StorageException("Invalid JSON: expected '{'");
        }
        i++;

        while (i < len) {
            i = skipWhitespace(json, i, len);
            if (i >= len) break;

            char c = json.charAt(i);
            if (c == '}') break;
            if (c == ',') {
                i++;
                continue;
            }

            // Parse key
            if (c != '"') {
                throw new StorageException("Invalid JSON: expected '\"' for key");
            }
            ParsedString key = parseString(json, i, len);
            i = key.endPos;

            // Skip colon
            i = skipWhitespace(json, i, len);
            if (i >= len || json.charAt(i) != ':') {
                throw new StorageException("Invalid JSON: expected ':'");
            }
            i++;
            i = skipWhitespace(json, i, len);

            if (i >= len) break;

            // Parse value - only capture string values
            if (json.charAt(i) == '"') {
                ParsedString value = parseString(json, i, len);
                i = value.endPos;
                result.put(key.value, value.value);
            } else {
                // Skip non-string values (objects, arrays, numbers, booleans, null)
                i = skipValue(json, i, len);
            }
        }

        return result;
    }

    /**
     * Extract a top-level string value by key from JSON.
     * Used for reading _default from profiles.json without full parsing.
     */
    static Optional<String> extractString(String json, String key) {
        String searchKey = "\"" + key + "\"";
        int idx = json.indexOf(searchKey);
        if (idx < 0) {
            return Optional.empty();
        }

        int i = idx + searchKey.length();
        int len = json.length();
        i = skipWhitespace(json, i, len);

        if (i >= len || json.charAt(i) != ':') {
            return Optional.empty();
        }
        i++;
        i = skipWhitespace(json, i, len);

        if (i >= len || json.charAt(i) != '"') {
            return Optional.empty();
        }

        return Optional.of(parseString(json, i, len).value);
    }

    /**
     * Parse a quoted JSON string starting at position start.
     * Returns the decoded string and the position after the closing quote.
     */
    private static ParsedString parseString(String json, int start, int len) {
        if (start >= len || json.charAt(start) != '"') {
            throw new StorageException("Invalid JSON: expected '\"'");
        }
        StringBuilder sb = new StringBuilder();
        int i = start + 1;
        while (i < len) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < len) {
                char next = json.charAt(i + 1);
                switch (next) {
                    case '"', '\\', '/' -> sb.append(next);
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    default -> {
                        sb.append('\\');
                        sb.append(next);
                    }
                }
                i += 2;
            } else if (c == '"') {
                return new ParsedString(sb.toString(), i + 1);
            } else {
                sb.append(c);
                i++;
            }
        }
        throw new StorageException("Invalid JSON: unterminated string");
    }

    private static int skipWhitespace(String json, int i, int len) {
        while (i < len && Character.isWhitespace(json.charAt(i))) {
            i++;
        }
        return i;
    }

    private static int skipValue(String json, int i, int len) {
        if (i >= len) return i;
        char c = json.charAt(i);
        if (c == '{') {
            return skipBracketed(json, i, len, '{', '}');
        } else if (c == '[') {
            return skipBracketed(json, i, len, '[', ']');
        } else if (c == '"') {
            return parseString(json, i, len).endPos;
        } else {
            // number, boolean, null - read until delimiter
            while (i < len) {
                char ch = json.charAt(i);
                if (ch == ',' || ch == '}' || ch == ']' || Character.isWhitespace(ch)) {
                    break;
                }
                i++;
            }
            return i;
        }
    }

    private static int skipBracketed(String json, int i, int len, char open, char close) {
        int depth = 0;
        boolean inString = false;
        while (i < len) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i += 2;
                    continue;
                }
                if (c == '"') {
                    inString = false;
                }
            } else {
                if (c == '"') {
                    inString = true;
                } else if (c == open) {
                    depth++;
                } else if (c == close) {
                    depth--;
                    if (depth == 0) {
                        return i + 1;
                    }
                }
            }
            i++;
        }
        return i;
    }
}
