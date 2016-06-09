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

package org.wso2.carbon.identity.sso.samlnew.bean.message.response;

import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;

import java.util.List;

public class SAMLErrorResponse extends SAMLResponse {

    public SAMLErrorResponse(IdentityResponseBuilder responsebuilder) {
        super(responsebuilder);
    }

    public static class SAMLErrorResponseBuilder extends SAMLResponseBuilder {


        public SAMLErrorResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLErrorResponse build() {
            try {
                buildResponse();
            } catch (IdentityException e) {

            }
            return new SAMLErrorResponse(this);
        }

        /**
         * Build the error response
         *
         * @return
         */
        public Response buildResponse() throws IdentityException {
            String inResponseToID = ((SAMLMessageContext) this.context).getInResponseToID();
            List<String> statusCodes = ((SAMLMessageContext) this.context).getStatusCodeList();
            String statusMsg = ((SAMLMessageContext) this.context).getMessage();
            String destination = ((SAMLMessageContext) this.context).getDestination();

            if (statusCodes == null || statusCodes.isEmpty()) {
                throw IdentityException.error("No Status Values");
            }
//            this.response.setIssuer(SAMLSSOUtil.getIssuer());
//            Status status = new StatusBuilder().buildObject();
//            StatusCode statusCode = null;
//            for (String statCode : statusCodes) {
//                statusCode = buildStatusCode(statCode, statusCode);
//            }
//            status.setStatusCode(statusCode);
//            buildStatusMsg(status, statusMsg);
//            this.response.setStatus(status);
//            this.response.setVersion(SAMLVersion.VERSION_20);
//            response.setID(SAMLSSOUtil.createID());
//            if (inResponseToID != null) {
//                response.setInResponseTo(inResponseToID);
//            }
//            if (destination != null) {
//                response.setDestination(destination);
//            }
//            response.setIssueInstant(new DateTime());
//            return response;
            return null;
        }

        /**
         * Build the StatusCode for Status of Response
         *
         * @param parentStatusCode
         * @param childStatusCode
         * @return
         */
        private StatusCode buildStatusCode(String parentStatusCode, StatusCode childStatusCode) throws
                IdentityException {
            if (parentStatusCode == null) {
                throw IdentityException.error("Invalid SAML Response Status Code");
            }

            StatusCode statusCode = new StatusCodeBuilder().buildObject();
            statusCode.setValue(parentStatusCode);

            //Set the status Message
            if (childStatusCode != null) {
                statusCode.setStatusCode(childStatusCode);
                return statusCode;
            } else {
                return statusCode;
            }
        }

        /**
         * Set the StatusMessage for Status of Response
         *
         * @param statusMsg
         * @return
         */
        private Status buildStatusMsg(Status status, String statusMsg) {
            if (statusMsg != null) {
                StatusMessage statusMesssage = new StatusMessageBuilder().buildObject();
                statusMesssage.setMessage(statusMsg);
                status.setStatusMessage(statusMesssage);
            }
            return status;
        }
    }


}
