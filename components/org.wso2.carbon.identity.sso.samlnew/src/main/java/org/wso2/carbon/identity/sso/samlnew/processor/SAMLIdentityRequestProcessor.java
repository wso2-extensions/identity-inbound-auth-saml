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

import org.apache.commons.lang3.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.bean.message.request.SAMLIdentityRequest;
import org.wso2.carbon.identity.sso.samlnew.bean.message.response.SAMLResponse;
import org.wso2.carbon.identity.sso.samlnew.dto.SAMLSSOReqValidationResponseDTO;

import java.util.HashMap;

public abstract class SAMLIdentityRequestProcessor extends IdentityProcessor {
    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    @Override
    public int getPriority() {
        return 0;
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
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLIdentityRequest) identityRequest, new
                HashMap<String, String>());
        FrameworkLoginResponse.FrameworkLoginResponseBuilder builder = (FrameworkLoginResponse
                .FrameworkLoginResponseBuilder) buildResponseForFrameworkLogin(messageContext);
        return builder;
    }

    protected SAMLSSOReqValidationResponseDTO validateSPInitSSORequest(SAMLMessageContext messageContext) throws IdentityException{
         return new SAMLSSOReqValidationResponseDTO();
    }

    protected IdentityMessageContext getContextIfAvailable(IdentityRequest request) {
        String sessionDataKey = request.getParameter("sessionDataKey");
        IdentityMessageContext context = null;
        if(StringUtils.isNotBlank(sessionDataKey)) {
            context = InboundUtil.getContextFromCache(sessionDataKey);
        }
        return context;
    }


}
