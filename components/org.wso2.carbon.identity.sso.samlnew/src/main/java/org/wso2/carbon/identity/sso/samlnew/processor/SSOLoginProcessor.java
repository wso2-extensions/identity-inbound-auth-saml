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


import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLLoginResponse;

import java.util.HashMap;

public class SSOLoginProcessor extends IdentityProcessor {
    @Override
    public String getName() {
        return "SSOLoginProcessor";
    }

    public int getPriority() {
        return 0;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if(context != null) {
            if(context.getRequest() instanceof SAMLIdentityRequest){
                return true;
            }
        }
        return false;
    }

    @Override
    public SAMLLoginResponse.SAMLLoginResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

        SAMLMessageContext messageContext = (SAMLMessageContext)getContextIfAvailable(identityRequest);

//        if(messageContext.getAuthzUser() == null) { // authentication response
//
//            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHN_REQUEST, identityRequest);
//            AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext);
//
//            AuthenticatedUser authenticatedUser = null;
//            if(authnResult.isAuthenticated()) {
//                authenticatedUser = authnResult.getSubject();
//                messageContext.setAuthzUser(authenticatedUser);
//
//            } else {
//                throw OAuth2AuthnException.error("Resource owner authentication failed");
//            }
//
//            if (!OAuth2ServerConfig.getInstance().isSkipConsentPage()) {
//
//                String spName = ((ServiceProvider) messageContext.getParameter(OAuth2.OAUTH2_SERVICE_PROVIDER)).getApplicationName();
//
//                if (!OAuth2ConsentStore.getInstance().hasUserApprovedAppAlways(authenticatedUser, spName)) {
//                    return initiateResourceOwnerConsent(messageContext);
//                } else {
//                    messageContext.addParameter(OAuth2.CONSENT, "ApproveAlways");
//                }
//            } else {
//                messageContext.addParameter(OAuth2.CONSENT, "SkipOAuth2Consent");
//            }
//
//        }
//
//        // if this line is reached that means this is a consent response or consent is skipped due config or approve
//        // always. We set the inbound request to message context only if it has gone through consent process
//        // if consent consent was skipped due to configuration or approve always,
//        // authenticated request and authorized request are the same
//        if(!StringUtils.equals("ApproveAlways", (String)messageContext.getParameter(OAuth2.CONSENT)) &&
//                !StringUtils.equals("SkipOAuth2Consent", (String)messageContext.getParameter(OAuth2.CONSENT))) {
//            messageContext.addParameter(OAuth2.OAUTH2_RESOURCE_OWNER_AUTHZ_REQUEST, identityRequest);
//            processConsent(messageContext);
//        }
//        return buildAuthzResponse(messageContext);
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

}
