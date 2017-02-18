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

import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponse;
import org.wso2.carbon.identity.gateway.api.response.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.gateway.api.response.IdentityResponse;
import org.wso2.carbon.identity.saml.bean.SAMLConfigurations;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class HttpSAMLResponseFactory extends HttpIdentityResponseFactory {

    private static Logger log = LoggerFactory.getLogger(HttpSAMLResponseFactory.class);

    @Override
    public String getName() {
        return "HttpSAMLResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if (identityResponse instanceof SAMLLoginResponse || identityResponse instanceof SAMLErrorResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        create(builder, identityResponse);
        return builder;
//
    }

    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder builder,
                                                                   IdentityResponse identityResponse) {
        super.create(builder, identityResponse);
        if (identityResponse instanceof SAMLLoginResponse) {
            sendResponse(builder, identityResponse);
        } else {
            sendNotification(builder, identityResponse);
        }
    }

    private void sendResponse(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse
            identityResponse) {
        SAMLLoginResponse loginResponse = ((SAMLLoginResponse) identityResponse);

        String authenticatedIdPs = loginResponse.getAuthenticatedIdPs();
        String relayState = loginResponse.getRelayState();
        String acUrl = loginResponse.getAcsUrl();
        builder.setRedirectURL(acUrl);
        builder.setContentType("text/html");
        if (SAMLConfigurations.getInstance().getSsoResponseHtml() != null) {
            builder.setBody(getRedirectHtml(acUrl, relayState, authenticatedIdPs, loginResponse));
        } else {
            builder.setBody(getPostHtml(acUrl, relayState, authenticatedIdPs, loginResponse));
        }
        builder.setStatusCode(200);
    }

    private String getRedirectHtml(String acUrl, String relayState, String authenticatedIdPs, SAMLLoginResponse
            loginResponse) {
        String finalPage = null;
        String htmlPage = SAMLConfigurations.getInstance().getSsoResponseHtml();
        String pageWithAcs = htmlPage.replace("$acUrl", acUrl);
        String pageWithAcsResponse = pageWithAcs.replace("<!--$params-->", "<!--$params-->\n" + "<input " +
                "type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(loginResponse.getRespString
                ()) + "'>");
        String pageWithAcsResponseRelay = pageWithAcsResponse;

        if (relayState != null) {
            pageWithAcsResponseRelay = pageWithAcsResponse.replace("<!--$params-->", "<!--$params-->\n" + "<input" +
                    " type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState) + "'>");
        }

        if (StringUtils.isBlank(authenticatedIdPs)) {
            finalPage = pageWithAcsResponseRelay;
        } else {
            finalPage = pageWithAcsResponseRelay.replace(
                    "<!--$additionalParams-->",
                    "<input type='hidden' name='AuthenticatedIdPs' value='"
                            + Encode.forHtmlAttribute(authenticatedIdPs) + "'>");
        }
        if (log.isDebugEnabled()) {
            log.debug("samlsso_response.html " + finalPage);
        }
        return finalPage;
    }

    private String getPostHtml(String acUrl, String relayState, String authenticatedIdPs, SAMLLoginResponse
            loginResponse) {
        StringBuilder out = new StringBuilder();
        out.append("<html>");
        out.append("<body>");
        out.append("<p>You are now redirected back to " + Encode.forHtmlContent(acUrl));
        out.append(" If the redirection fails, please click the post button.</p>");
        out.append("<form method='post' action='" + Encode.forHtmlAttribute(acUrl) + "'>");
        out.append("<p>");
        out.append("<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(loginResponse
                .getRespString()) + "'>");

        if (relayState != null) {
            out.append("<input type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState) +
                    "'>");
        }

        if (StringUtils.isBlank(authenticatedIdPs)) {
            out.append("<input type='hidden' name='AuthenticatedIdPs' value='" +
                    Encode.forHtmlAttribute(authenticatedIdPs) + "'>");
        }

        out.append("<button type='submit'>POST</button>");
        out.append("</p>");
        out.append("</form>");
        out.append("<script type='text/javascript'>");
        out.append("document.forms[0].submit();");
        out.append("</script>");
        out.append("</body>");
        out.append("</html>");
        return out.toString();
    }

    private void sendNotification(HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse
                                  identityResponse) {
        SAMLErrorResponse errorResponse = ((SAMLErrorResponse) identityResponse);
        String redirectURL = SAMLSSOUtil.getNotificationEndpoint();
        Map<String, String[]> queryParams = new HashMap();

        //TODO Send status codes rather than full messages in the GET request
        try {
            queryParams.put(SAMLSSOConstants.STATUS, new String[]{URLEncoder.encode(errorResponse.getStatus(),
                    StandardCharsets.UTF_8.name())});
            queryParams.put(SAMLSSOConstants.STATUS_MSG, new String[]{URLEncoder.encode(errorResponse.getMessageLog()
                    , StandardCharsets.UTF_8.name())});

            if (StringUtils.isNotEmpty(errorResponse.getErrorResponse())) {
                queryParams.put(SAMLSSOConstants.SAML_RESP, new String[]{URLEncoder.encode(errorResponse
                        .getErrorResponse(), StandardCharsets.UTF_8.name())});
            }

            if (StringUtils.isNotEmpty(errorResponse.getAcsUrl())) {
                queryParams.put(SAMLSSOConstants.ASSRTN_CONSUMER_URL, new String[]{URLEncoder.encode(errorResponse
                        .getAcsUrl(), StandardCharsets.UTF_8.name())});
            }
        } catch (UnsupportedEncodingException e) {

        }
        builder.setStatusCode(302);
        builder.setParameters(queryParams);
        builder.setRedirectURL(redirectURL);
    }

    @Override
    public int getPriority() {
        return 31;
    }
}
