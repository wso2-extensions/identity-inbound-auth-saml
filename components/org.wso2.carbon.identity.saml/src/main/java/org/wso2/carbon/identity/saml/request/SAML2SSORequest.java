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
package org.wso2.carbon.identity.saml.request;

import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.gateway.request.ClientAuthenticationRequest;

/**
 * The abstract model representing an AuthnRequest sent by the service
 * provider.
 */
public abstract class SAML2SSORequest extends ClientAuthenticationRequest {

    public SAML2SSORequest(SAMLGatewayRequestBuilder builder) {
        super(builder);
    }

    public String getRelayState() {
        return getParameter(SAML2AuthConstants.RELAY_STATE);
    }

    /**
     * Builder used to build a SAML2SSORequest.
     */
    public static class SAMLGatewayRequestBuilder
            extends ClientAuthenticationRequest.ClientAuthenticationRequestBuilder {

        public SAMLGatewayRequestBuilder() {
            super();
        }
    }
}
