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
