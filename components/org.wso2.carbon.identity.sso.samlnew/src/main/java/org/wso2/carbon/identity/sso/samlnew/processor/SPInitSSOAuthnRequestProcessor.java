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
package org.wso2.carbon.identity.sso.samlnew.processor;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;

import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.sso.samlnew.validators.SSOAuthnRequestValidator;

import java.util.HashMap;

public class SPInitSSOAuthnRequestProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SPInitSSOAuthnRequestProcessor.class);
    private String relyingParty;

    @Override
    public String getName() {
        return "SPInitSSOAuthnRequestProcessor";
    }

    @Override
    public int getPriority() {
        return -2;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return this.relyingParty;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLIdentityRequest && ((SAMLIdentityRequest) identityRequest).getSamlRequest
                () != null) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLIdentityRequest) identityRequest, new
                HashMap<String, String>());
        try {
            validateSPInitSSORequest(messageContext);
        } catch (IdentityException e) {
            throw new FrameworkException("Error while building SAML Response.");
        }
        FrameworkLoginResponse.FrameworkLoginResponseBuilder builder = buildResponseForFrameworkLogin(messageContext);
        return builder;
    }


    protected boolean validateSPInitSSORequest(SAMLMessageContext messageContext) throws IdentityException {
        SAMLIdentityRequest identityRequest = messageContext.getRequest();
        String decodedRequest;
        if (identityRequest.isRedirect()) {
            decodedRequest = SAMLSSOUtil.decode(identityRequest.getSamlRequest());
        } else {
            decodedRequest = SAMLSSOUtil.decodeForPost(identityRequest.getSamlRequest());
        }
        XMLObject request = SAMLSSOUtil.unmarshall(decodedRequest);
        if (request instanceof AuthnRequest) {
            messageContext.setIdpInitSSO(false);
            messageContext.setAuthnRequest((AuthnRequest) request);
            messageContext.setTenantDomain(SAMLSSOUtil.getTenantDomainFromThreadLocal());
            this.relyingParty = ((AuthnRequest) request).getIssuer().getValue();
            //messageContext.setRpSessionId(identityRequest.getParameter(MultitenantConstants.SSO_AUTH_SESSION_ID));
            SSOAuthnRequestValidator reqValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(messageContext);
            return reqValidator.validate();
        }
        return false;
    }
}
