package org.wso2.carbon.identity.saml.exception;


import org.wso2.carbon.identity.gateway.api.exception.GatewayRuntimeException;

public class SAMLRuntimeException extends GatewayRuntimeException {
    public SAMLRuntimeException(String message) {
        super(message);
    }

    public SAMLRuntimeException(String errorCode, String message) {
        super(errorCode, message);
    }

    public SAMLRuntimeException(String errorCode, String message, Throwable cause) {
        super(errorCode, message, cause);
    }

    public SAMLRuntimeException(String errorCode, Throwable cause) {
        super(errorCode, cause);
    }
}
