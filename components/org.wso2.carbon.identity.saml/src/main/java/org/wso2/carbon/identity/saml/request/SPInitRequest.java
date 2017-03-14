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

import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;

import java.io.UnsupportedEncodingException;

/**
 * SP Initiated SAML2 SSO Request.
 */
public class SPInitRequest extends SAML2SSORequest {

    private static Logger logger = LoggerFactory.getLogger(SPInitRequest.class);
    private transient AuthnRequest authnRequest;

    public SPInitRequest(SAMLSpInitRequestBuilder builder) {
        super(builder);
    }

    public String getSAMLRequest() {
        if (this.getBodyParameter(SAML2AuthConstants.SAML_REQUEST) != null) {
            return this.getBodyParameter(SAML2AuthConstants.SAML_REQUEST);
        } else {
            try {
                return this.getQueryParameter(SAML2AuthConstants.SAML_REQUEST);
            } catch (UnsupportedEncodingException e) {
                throw new SAML2SSORuntimeException("Failed to URL-decode the SAMLRequest.", e);
            }
        }
    }

    public String getSignature() {
        if (this.getBodyParameter(SAML2AuthConstants.SIGNATURE) != null) {
            return this.getBodyParameter(SAML2AuthConstants.SIGNATURE);
        } else {
            try {
                return this.getQueryParameter(SAML2AuthConstants.SIGNATURE);
            } catch (UnsupportedEncodingException e) {
                throw new SAML2SSORuntimeException("Failed to decode the Signature.", e);
            }
        }
    }

    public String getSignatureAlgorithm() {
        if (this.getBodyParameter(SAML2AuthConstants.SIG_ALG) != null) {
            return this.getBodyParameter(SAML2AuthConstants.SIG_ALG);
        } else {
            try {
                return this.getQueryParameter(SAML2AuthConstants.SIG_ALG);
            } catch (UnsupportedEncodingException e) {
                throw new SAML2SSORuntimeException("Failed to decode the Signature Algorithm.", e);
            }
        }
    }

    public boolean isRedirect() {
        return !SAML2AuthConstants.Config.Value.POST.equalsIgnoreCase(this.httpMethod);
    }

    public AuthnRequest getAuthnRequest() throws SAML2SSORuntimeException {

        if (authnRequest == null) {
            String decodedRequest;
            if (isRedirect()) {
                decodedRequest = SAML2AuthUtils.decodeForRedirect(getSAMLRequest());
            } else {
                decodedRequest = SAML2AuthUtils.decodeForPost(getSAMLRequest());
            }
            XMLObject request = SAML2AuthUtils.unmarshall(decodedRequest);
            if (request instanceof AuthnRequest) {
                AuthnRequest authnRequest = (AuthnRequest) request;
                this.authnRequest = authnRequest;
            } else {
                // throwing a RuntimeException here to avoid handling SAML2SSOClientException in all the places
                throw new SAML2SSORuntimeException("", "");
            }
        }
        return authnRequest;
    }

    public static class SAMLSpInitRequestBuilder extends SAMLGatewayRequestBuilder {

        public SAMLSpInitRequestBuilder() {
        }

        @Override
        public SPInitRequest build() {
            return new SPInitRequest(this);
        }
    }
}
