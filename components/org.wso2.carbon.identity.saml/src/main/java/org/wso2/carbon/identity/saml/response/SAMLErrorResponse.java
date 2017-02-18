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

import org.wso2.carbon.identity.gateway.api.context.IdentityMessageContext;
import org.wso2.carbon.identity.gateway.api.response.IdentityResponse;

public class SAMLErrorResponse extends SAMLResponse {

    private String errorResponse;
    private String acsUrl;
    private String status;
    private String messageLog;

    public SAMLErrorResponse(IdentityResponse.IdentityResponseBuilder responsebuilder) {

        super(responsebuilder);
        this.errorResponse = ((SAMLErrorResponseBuilder) responsebuilder).errorResponse;
        this.acsUrl = ((SAMLErrorResponseBuilder) responsebuilder).acsUrl;
        this.status = ((SAMLErrorResponseBuilder) responsebuilder).status;
        this.messageLog = ((SAMLErrorResponseBuilder) responsebuilder).messageLog;
    }

    public String getErrorResponse() {
        return errorResponse;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getStatus() {
        return status;
    }

    public String getMessageLog() {
        return messageLog;
    }

    public static class SAMLErrorResponseBuilder extends SAMLResponseBuilder {

        private String errorResponse;
        private String acsUrl;
        private String status;
        private String messageLog;

        public SAMLErrorResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLErrorResponse build() {
            return new SAMLErrorResponse(this);
        }

        public SAMLErrorResponseBuilder setErrorResponse(String response) {
            this.errorResponse = response;
            return this;
        }

        public SAMLErrorResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLErrorResponseBuilder setStatus(String status) {
            this.status = status;
            return this;
        }

        public SAMLErrorResponseBuilder setMessageLog(String messageLog) {
            this.messageLog = messageLog;
            return this;
        }

    }
}
