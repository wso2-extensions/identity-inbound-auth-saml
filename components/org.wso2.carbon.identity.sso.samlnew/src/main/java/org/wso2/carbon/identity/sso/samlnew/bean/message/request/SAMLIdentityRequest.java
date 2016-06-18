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

package org.wso2.carbon.identity.sso.samlnew.bean.message.request;

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLIdentityRequest extends IdentityRequest {
    private String samlRequest;
    private String signature;
    private String sigAlg;
    private String relayState;

    public SAMLIdentityRequest(SAMLIdentityRequestBuilder builder) {
        super(builder);
        this.samlRequest = builder.samlRequest;
        this.signature = builder.signature;
        this.sigAlg = builder.sigAlg;
        this.relayState = builder.relayState;
    }

    public String getSignature() {
        return signature;
    }

    public String getSigAlg() {
        return sigAlg;
    }

    public String getSamlRequest() {
        return samlRequest;
    }

    public String getRelayState() {
        return relayState;
    }

    public static class SAMLIdentityRequestBuilder extends IdentityRequestBuilder {

        private String samlRequest;
        private String signature;
        private String sigAlg;
        private String relayState;

        public SAMLIdentityRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAMLIdentityRequestBuilder() {
        }

        @Override
        public SAMLIdentityRequest build() {
            return new SAMLIdentityRequest(this);
        }

        public SAMLIdentityRequestBuilder setSignature(String signature) {
            this.signature = signature;
            return this;
        }

        public SAMLIdentityRequestBuilder setSamlRequest(String samlRequest) {
            this.samlRequest = samlRequest;
            return this;
        }

        public SAMLIdentityRequestBuilder setSigAlg(String sigAlg) {
            this.sigAlg = sigAlg;
            return this;
        }

        public SAMLIdentityRequestBuilder setRelayState(String relayState){
            this.relayState = relayState;
            return this;
        }
    }
}
