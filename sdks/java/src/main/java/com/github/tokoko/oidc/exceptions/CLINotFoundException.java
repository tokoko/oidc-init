package com.github.tokoko.oidc.exceptions;

public class CLINotFoundException extends OidcException {

    public CLINotFoundException(String message) {
        super(message);
    }

    public CLINotFoundException(String message, Throwable cause) {
        super(message, cause);
    }
}
