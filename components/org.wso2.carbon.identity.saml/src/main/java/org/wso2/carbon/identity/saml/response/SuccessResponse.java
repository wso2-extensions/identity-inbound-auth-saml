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
package org.wso2.carbon.identity.saml.response;

import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.gateway.api.context.GatewayMessageContext;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.saml.bean.MessageContext;

public class SuccessResponse extends SAML2SSOResponse {

    private String respString;
    private String relayState;
    private String acsUrl;

    protected SuccessResponse(GatewayResponseBuilder builder) {
        super(builder);
        this.respString = ((SAMLLoginResponseBuilder) builder).respString;
        this.relayState = ((SAMLLoginResponseBuilder) builder).relayState;
        this.acsUrl = ((SAMLLoginResponseBuilder) builder).acsUrl;
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

    public MessageContext getContext() {
        return (MessageContext) this.context;
    }

    public static class SAMLLoginResponseBuilder extends SAMLResponseBuilder {

        private String respString;
        private String relayState;
        private String acsUrl;

        public SAMLLoginResponseBuilder(GatewayMessageContext context) {
            super(context);
        }

        @Override
        public GatewayResponse build() {
            return new SuccessResponse(this);
        }

        public SAMLLoginResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
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
