package com.github.tokoko.oidc.exceptions;

public class TokenNotFoundException extends OidcException {

    public TokenNotFoundException(String message) {
        super(message);
    }

    public TokenNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
