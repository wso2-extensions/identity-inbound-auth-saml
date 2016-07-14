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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.samlnew.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.identity.sso.samlnew.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class HttpSAMLResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(HttpSAMLResponseFactory.class);

    @Override
    public String getName() {
        return "HttpSAMLResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof SAMLLoginResponse || identityResponse instanceof SAMLErrorResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        if(identityResponse instanceof SAMLLoginResponse){
            return sendResponse(identityResponse);
        }else{
            return sendNotification(identityResponse);
        }
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendResponse(IdentityResponse identityResponse) {
        SAMLLoginResponse loginResponse = ((SAMLLoginResponse) identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();

        String authenticatedIdPs = loginResponse.getAuthenticatedIdPs();
        String relayState = loginResponse.getRelayState();
        String acUrl = getACSUrlWithTenantPartitioning(loginResponse.getAcsUrl(), loginResponse.getTenantDomain());
        if (IdentitySAMLSSOServiceComponent.getSsoRedirectHtml() != null) {

            String finalPage = null;
            String htmlPage = IdentitySAMLSSOServiceComponent.getSsoRedirectHtml();
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

            builder.setBody(finalPage);
            if (log.isDebugEnabled()) {
                log.debug("samlsso_response.html " + finalPage);
            }

        } else {
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
            builder.setBody(out.toString());
        }
//        builder.setHeaders(response.getHeaders());
//        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
//                OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
//        builder.addHeader(OAuth2.Header.PRAGMA,
//                OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        builder.setStatusCode(HttpServletResponse.SC_OK);
        return builder;
    }

    private HttpIdentityResponse.HttpIdentityResponseBuilder sendNotification(IdentityResponse identityResponse) {
        SAMLErrorResponse errorResponse = ((SAMLErrorResponse) identityResponse);
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse
                .HttpIdentityResponseBuilder();
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
        builder.setStatusCode(HttpServletResponse.SC_MOVED_TEMPORARILY);
        builder.setParameters(queryParams);
        builder.setRedirectURL(redirectURL);
        return builder;
    }
    @Override
    public void create(HttpIdentityResponse.HttpIdentityResponseBuilder httpIdentityResponseBuilder, IdentityResponse
            identityResponse) {

    }

    private String getACSUrlWithTenantPartitioning(String acsUrl, String tenantDomain) {
        String acsUrlWithTenantDomain = acsUrl;
        if (tenantDomain != null && "true".equals(IdentityUtil.getProperty(
                IdentityConstants.ServerConfig.SSO_TENANT_PARTITIONING_ENABLED))) {
            acsUrlWithTenantDomain =
                    acsUrlWithTenantDomain + "?" +
                            MultitenantConstants.TENANT_DOMAIN + "=" + tenantDomain;
        }
        return acsUrlWithTenantDomain;
    }
}
