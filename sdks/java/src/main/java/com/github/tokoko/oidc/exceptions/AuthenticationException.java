package com.github.tokoko.oidc.exceptions;

public class AuthenticationException extends OidcException {

    public AuthenticationException(String message) {
        super(message);
    }

    public AuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
