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
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkClientException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.exception.SAML2ClientException;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class SAMLIdentityRequestFactory extends HttpIdentityRequestFactory {

    private static Log log = LogFactory.getLog(SAMLIdentityRequestFactory.class);
    @Override
    public String getName() {
        return "SAMLIdentityRequestFactory";
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
        return -3;
    }

    @Override
    public SAMLIdentityRequest.SAMLIdentityRequestBuilder create(HttpServletRequest request,
                                                         HttpServletResponse response) throws SAML2ClientException {

        SAMLIdentityRequest.SAMLIdentityRequestBuilder builder = new SAMLIdentityRequest.SAMLIdentityRequestBuilder
                (request, response);
        try {
            super.create(builder, request, response);
        } catch (FrameworkClientException e) {
            throw SAML2ClientException.error("Error occurred while creating the Identity Request Builder",e);
        }
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder handleException(FrameworkClientException exception,
                                                                            HttpServletRequest request,
                                                                            HttpServletResponse response) {

            HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                    .HttpIdentityResponseBuilder();
            String redirectURL = SAMLSSOUtil.getNotificationEndpoint();
            Map<String, String[]> queryParams = new HashMap();
            //TODO Send status codes rather than full messages in the GET request
            try {
                queryParams.put(SAMLSSOConstants.STATUS, new String[]{URLEncoder.encode(((SAML2ClientException)
                        exception).getExceptionStatus(), StandardCharsets.UTF_8.name())});
                queryParams.put(SAMLSSOConstants.STATUS_MSG, new String[]{URLEncoder.encode(((SAML2ClientException)
                        exception).getExceptionMessage(), StandardCharsets.UTF_8.name())});
                if (exception.getMessage() != null) {
                    queryParams.put(SAMLSSOConstants.SAML_RESP, new String[]{URLEncoder.encode(exception.getMessage()
                            , StandardCharsets.UTF_8.name())});
                }
                if (((SAML2ClientException) exception).getACSUrl() != null) {
                    queryParams.put(SAMLSSOConstants.ASSRTN_CONSUMER_URL, new String[]{URLEncoder.encode((
                            (SAML2ClientException) exception).getACSUrl(), StandardCharsets.UTF_8.name())});
                }
                builder.setParameters(queryParams);
            } catch (UnsupportedEncodingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error while encoding query parameters.");
                }
            }
            builder.setRedirectURL(redirectURL);
            builder.setStatusCode(HttpServletResponse.SC_MOVED_TEMPORARILY);
            return builder;
    }
}
