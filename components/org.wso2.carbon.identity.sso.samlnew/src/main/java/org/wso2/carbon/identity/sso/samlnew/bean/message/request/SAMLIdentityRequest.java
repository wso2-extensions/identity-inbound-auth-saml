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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;

public class SAMLIdentityRequest extends IdentityRequest {

    private static Log log = LogFactory.getLog(SAMLIdentityRequest.class);
    public SAMLIdentityRequest(SAMLIdentityRequestBuilder builder) {
        super(builder);
    }

    public String getSignature() {
        if(this.getParameter(SAMLSSOConstants.SIGNATURE) != null) {
            return this.getParameter(SAMLSSOConstants.SIGNATURE);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SIGNATURE);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Signature ", e);
                }
            }
        }
        return null;
    }

    public String getSigAlg() {
        if(this.getParameter(SAMLSSOConstants.SIG_ALG) != null) {
            return this.getParameter(SAMLSSOConstants.SIG_ALG);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SIG_ALG);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Signature Algorithm ", e);
                }
            }
        }
        return null;
    }

    public String getSamlRequest() {
        if(this.getParameter(SAMLSSOConstants.SAML_REQUEST) != null) {
            return this.getParameter(SAMLSSOConstants.SAML_REQUEST);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SAML_REQUEST);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the SAML Request ", e);
                }
            }
        }
        return null;
    }

    public String getRelayState() {
        if(this.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return this.getParameter(SAMLSSOConstants.RELAY_STATE);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.RELAY_STATE);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Relay State ", e);
                }
            }
        }
        return null;
    }

    public boolean isRedirect() {
        return this.getMethod() == SAMLSSOConstants.GET_METHOD;
    }

    public static class SAMLIdentityRequestBuilder extends IdentityRequestBuilder {
        public SAMLIdentityRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAMLIdentityRequestBuilder() {
        }

        @Override
        public SAMLIdentityRequest build() {
            return new SAMLIdentityRequest(this);
        }
    }
}
