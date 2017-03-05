/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.saml.response;

import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.context.GatewayMessageContext;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;

public class SAMLLoginResponse extends SAMLResponse {

    private String respString;
    private String relayState;
    private String acsUrl;
    private String subject;
    private String authenticatedIdPs;

    protected SAMLLoginResponse(GatewayResponseBuilder builder) {
        super(builder);
        this.respString = ((SAMLLoginResponseBuilder) builder).respString;
        this.relayState = ((SAMLLoginResponseBuilder) builder).relayState;
        this.acsUrl = ((SAMLLoginResponseBuilder) builder).acsUrl;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getAuthenticatedIdPs() {
        return authenticatedIdPs;
    }

    public SAMLMessageContext getContext() {
        return (SAMLMessageContext) this.context;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getRespString() {
        return respString;
    }

    public String getSubject() {
        return subject;
    }


    public static class SAMLLoginResponseBuilder extends SAMLResponseBuilder {

        private static Logger log = LoggerFactory.getLogger(SAMLLoginResponseBuilder.class);

        private String respString;
        private String relayState;
        private String acsUrl;
        private String subject;
        private String authenticatedIdPs;
        private String tenantDomain;

        public SAMLLoginResponseBuilder(GatewayMessageContext context) {
            super(context);
        }

        @Override
        public GatewayResponse build() {
            return new SAMLLoginResponse(this);
        }

        public SAMLLoginResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLLoginResponseBuilder setAuthenticatedIdPs(String authenticatedIdPs) {
            this.authenticatedIdPs = authenticatedIdPs;
            return this;
        }

        public SAMLLoginResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAMLLoginResponseBuilder setRespString(String respString) {
            this.respString = respString;
            return this;
        }

        public SAMLLoginResponseBuilder setSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public SAMLLoginResponseBuilder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        private Status buildStatus(String status, String statMsg) {

            Status stat = new StatusBuilder().buildObject();

            // Set the status code
            StatusCode statCode = new StatusCodeBuilder().buildObject();
            statCode.setValue(status);
            stat.setStatusCode(statCode);

            // Set the status Message
            if (statMsg != null) {
                StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
                statMesssage.setMessage(statMsg);
                stat.setStatusMessage(statMesssage);
            }

            return stat;
        }
    }
}
