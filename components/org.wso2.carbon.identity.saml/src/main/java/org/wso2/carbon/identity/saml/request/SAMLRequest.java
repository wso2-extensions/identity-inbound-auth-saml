package org.wso2.carbon.identity.saml.request;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.request.ClientAuthenticationRequest;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;

/**
 * SAMLRequest is based request for SAML protocol.
 */
public abstract class SAMLRequest extends ClientAuthenticationRequest {

    private static Logger log = LoggerFactory.getLogger(SAMLRequest.class);

    /**
     * @param builder
     */
    public SAMLRequest(SAMLGatewayRequestBuilder builder) {
        super(builder);
    }

    /**
     * Get the relay state from the request parameter. This can be come through either
     * query param or body param.
     *
     * @return String
     * @throws SAMLServerException
     */
    public String getRelayState() {
        return getParameter(SAMLSSOConstants.RELAY_STATE);
    }

    /**
     * Check whether the request is GET or not.
     *
     * @return
     */


    public static class SAMLGatewayRequestBuilder
            extends ClientAuthenticationRequest.ClientAuthenticationRequestBuilder {

        public SAMLGatewayRequestBuilder() {
            super();
        }
    }
}
