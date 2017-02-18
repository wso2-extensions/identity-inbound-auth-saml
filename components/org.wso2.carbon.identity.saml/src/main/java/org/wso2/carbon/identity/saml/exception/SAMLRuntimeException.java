package org.wso2.carbon.identity.saml.exception;


import org.wso2.carbon.identity.gateway.api.exception.FrameworkRuntimeException;

public class SAMLRuntimeException extends FrameworkRuntimeException {
    protected SAMLRuntimeException(String errorDescription) {
        super(errorDescription);
    }

    protected SAMLRuntimeException(String errorDescription, Throwable cause) {
        super(errorDescription, cause);
    }

    public static SAMLRuntimeException error(String errorDescription) {
        return new SAMLRuntimeException(errorDescription);
    }

    public static SAMLRuntimeException error(String errorDescription, Throwable cause) {
        return new SAMLRuntimeException(errorDescription, cause);
    }
}
