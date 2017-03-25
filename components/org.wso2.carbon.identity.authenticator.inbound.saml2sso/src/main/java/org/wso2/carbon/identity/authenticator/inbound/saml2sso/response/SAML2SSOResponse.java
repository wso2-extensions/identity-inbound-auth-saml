/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.authenticator.inbound.saml2sso.response;

import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.impl.ResponseBuilder;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.model.Config;
import org.wso2.carbon.identity.gateway.api.context.GatewayMessageContext;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;

/**
 * The SAML2 SSO Response returned to the service provider.
 */
public class SAML2SSOResponse extends GatewayResponse {

    private static final long serialVersionUID = 4048136330306085380L;

    private transient Response response = null;
    private String respString;
    private String relayState;
    private String acsUrl;

    protected SAML2SSOResponse(SAML2SSOResponseBuilder builder) {
        super(builder);
        this.response = builder.response;
        this.respString = builder.respString;
        this.relayState = builder.relayState;
        this.acsUrl = builder.acsUrl;
    }

    public Response getResponse() {
        if (response == null) {
            String decodedRequest;
            decodedRequest = SAML2AuthUtils.decodeForPost(getRespString());
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            if (request instanceof Response) {
                Response response = (Response) request;
                this.response = response;
            } else {
                // throwing a unchecked here to avoid handling checked exception in all the places
                SAML2SSORuntimeException ex =
                        new SAML2SSORuntimeException(StatusCode.RESPONDER_URI, "SAMLResponse not a Response.");
                ex.setAcsUrl(Config.getInstance().getErrorPageUrl());
                throw ex;
            }
        }
        return response;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getRespString() {
        return respString;
    }

// Need to enable debug logging for gateway during tests to uncomment this
//    @Override
//    public String toString() {
//        final StringBuffer sb = new StringBuffer("SAML2SSOResponse{");
//        sb.append("respString='").append(respString).append('\'');
//        sb.append(", acsUrl='").append(acsUrl).append('\'');
//        sb.append(", relayState='").append(relayState).append('\'');
//        sb.append('}');
//        return sb.toString();
//    }

    /**
     * Builder used to build a SAML2SSOResponse.
     */
    public static class SAML2SSOResponseBuilder extends GatewayResponseBuilder {

        private Response response;
        private String respString;
        private String relayState;
        private String acsUrl;

        public SAML2SSOResponseBuilder(GatewayMessageContext context) {
            super(context);
            ResponseBuilder responseBuilder = new ResponseBuilder();
            this.response = responseBuilder.buildObject();
        }

        public SAML2SSOResponseBuilder setResponse(Response response) {
            this.response = response;
            return this;
        }

        public SAML2SSOResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public SAML2SSOResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAML2SSOResponseBuilder setRespString(String respString) {
            this.respString = respString;
            return this;
        }

        public SAML2SSOResponse build() {
            return new SAML2SSOResponse(this);
        }
    }
}
