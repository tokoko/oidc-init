# oidc-init Java SDK

Thin Java wrapper for reading cached OIDC tokens managed by the [`oidc` CLI](https://github.com/tokoko/oidc-init). Zero runtime dependencies.

## Install

Gradle:
```kotlin
implementation("com.github.tokoko:oidc-init:0.1.0")
```

Maven:
```xml
<dependency>
    <groupId>com.github.tokoko</groupId>
    <artifactId>oidc-init</artifactId>
    <version>0.1.0</version>
</dependency>
```

The `oidc` CLI binary must be in `$PATH` (or set `OIDC_CLI_PATH`) for auto-reauthentication.

## Usage

```java
import com.github.tokoko.oidc.OidcClient;

var client = new OidcClient();

// From default profile
String token = client.getToken();

// From a specific profile
String token = client.getToken("my-keycloak");
```

## API

All methods are on `OidcClient`:

| Method | Description |
|---|---|
| `getToken(storageKey?)` | Get access token (auto-reauths if expired) |
| `getTokens(storageKey?)` | Get all tokens as `Map<String, String>` |
| `getTokenPath(storageKey?)` | Get path to raw `.token` file |
| `listTokens(includeExpired)` | List available storage keys |
| `isTokenValid(storageKey)` | Check if token exists and is valid |
| `purgeTokens()` | Delete all stored tokens |

## Error Handling

```java
import com.github.tokoko.oidc.OidcClient;
import com.github.tokoko.oidc.exceptions.*;

var client = new OidcClient();
try {
    String token = client.getToken("my-profile");
} catch (CLINotFoundException e) {
    // oidc binary not found
} catch (AuthenticationException e) {
    // CLI re-auth failed
} catch (TokenNotFoundException e) {
    // token file missing
} catch (ProfileNotFoundException e) {
    // no key given, no default set
}
```

## Requirements

- Java >= 17
- `oidc` CLI binary (for re-authentication)
