package com.github.tokoko.oidc.exceptions;

public class StorageException extends OidcException {

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
