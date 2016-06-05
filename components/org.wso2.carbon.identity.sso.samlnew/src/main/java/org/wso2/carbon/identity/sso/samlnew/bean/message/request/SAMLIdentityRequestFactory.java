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

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.exception.SAML2ClientException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SAMLIdentityRequestFactory extends HttpIdentityRequestFactory {
    @Override
    public String getName() {
        return "SAMLInboundRequestFactory";
    }

    @Override
    public boolean canHandle(HttpServletRequest request, HttpServletResponse response) {
        if(StringUtils.isNotBlank(request.getParameter(SAMLSSOConstants.SAML_REQUEST))){
            return true;
        }
        return false;
    }

    @Override
    public int getPriority() {
        return 1;
    }
    public SAMLIdentityRequest.SAMLIdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws SAML2ClientException {

        SAMLIdentityRequest.SAMLIdentityRequestBuilder builder = new SAMLIdentityRequest.SAMLIdentityRequestBuilder
                (request, response);
        builder.setSamlRequest(request.getParameter(SAMLSSOConstants.SAML_REQUEST));
        builder.setSignature(request.getParameter(SAMLSSOConstants.SIGNATURE));
        builder.setSigAlg(request.getParameter(SAMLSSOConstants.SIG_ALG));
        return builder;
    }
}
