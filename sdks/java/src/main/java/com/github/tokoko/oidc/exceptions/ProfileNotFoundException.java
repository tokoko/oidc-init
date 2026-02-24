package com.github.tokoko.oidc.exceptions;

public class ProfileNotFoundException extends OidcException {

    public ProfileNotFoundException(String message) {
        super(message);
    }

    public ProfileNotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
