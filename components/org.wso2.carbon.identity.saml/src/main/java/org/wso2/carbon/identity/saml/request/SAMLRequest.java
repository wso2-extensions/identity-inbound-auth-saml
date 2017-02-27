package org.wso2.carbon.identity.saml.request;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.processor.request.ClientAuthenticationRequest;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;

public class SAMLRequest extends ClientAuthenticationRequest {

    private static Logger log = LoggerFactory.getLogger(SAMLRequest.class);


    public SAMLRequest(SAMLGatewayRequestBuilder builder) {
        super(builder);
    }

    public String getRelayState() {
        String parameter = getParameter(SAMLSSOConstants.RELAY_STATE);
        return parameter;
    }

    public boolean isRedirect() {
        return this.getHttpMethod() == SAMLSSOConstants.GET_METHOD;
    }

    public static class SAMLGatewayRequestBuilder
            extends ClientAuthenticationRequest.ClientAuthenticationRequestBuilder {

        public SAMLGatewayRequestBuilder() {
            super();
        }
    }
}
