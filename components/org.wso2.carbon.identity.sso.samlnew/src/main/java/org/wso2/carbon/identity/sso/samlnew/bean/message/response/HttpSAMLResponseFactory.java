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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.owasp.encoder.Encode;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.PrintWriter;

public class HttpSAMLResponseFactory extends HttpIdentityResponseFactory {

    private static Log log = LogFactory.getLog(HttpSAMLResponseFactory.class);

    @Override
    public String getName() {
        return "HttpSAMLResponseFactory";
    }

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof SAMLLoginResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(IdentityResponse identityResponse) {

        SAMLLoginResponse loginResponse = ((SAMLLoginResponse)identityResponse);
        SAMLMessageContext messageContext = loginResponse.getContext();
        AuthenticationResult authnResult = messageContext.getAuthenticationResult();
        AuthnRequest authnRequest = messageContext.getAuthnRequest();
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();


        //@TODO assign following values
        String authenticatedIdPs = "";
        String relayState = messageContext.getRelayState();
        String acUrl = getACSUrlWithTenantPartitioning(authnRequest.getAssertionConsumerServiceURL(), messageContext.getTenantDomain());
        if (IdentitySAMLSSOServiceComponent.getSsoRedirectHtml() != null) {

            String finalPage = null;
            String htmlPage = IdentitySAMLSSOServiceComponent.getSsoRedirectHtml();
            String pageWithAcs = htmlPage.replace("$acUrl", acUrl);
            String pageWithAcsResponse = pageWithAcs.replace("<!--$params-->", "<!--$params-->\n" + "<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(loginResponse.getRespString()) + "'>");
            String pageWithAcsResponseRelay = pageWithAcsResponse;

            if(relayState != null) {
                pageWithAcsResponseRelay = pageWithAcsResponse.replace("<!--$params-->", "<!--$params-->\n" + "<input type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState)+ "'>");
            }

            if (authnResult.getAuthenticatedIdPs() == null || authnResult.getAuthenticatedIdPs().isEmpty()) {
                finalPage = pageWithAcsResponseRelay;
            } else {
                finalPage = pageWithAcsResponseRelay.replace(
                        "<!--$additionalParams-->",
                        "<input type='hidden' name='AuthenticatedIdPs' value='"
                                + Encode.forHtmlAttribute(authnResult.getAuthenticatedIdPs()) + "'>");
            }

            builder.setBody(finalPage);
            builder.setStatusCode(200);
            if (log.isDebugEnabled()) {
                log.debug("samlsso_response.html " + finalPage);
            }

        } else {
            StringBuilder out = new StringBuilder();
            out.append("<html>");
            out.append("<body>");
            out.append("<p>You are now redirected back to " + Encode.forHtmlContent(authnRequest.getAssertionConsumerServiceURL()));
            out.append(" If the redirection fails, please click the post button.</p>");
            out.append("<form method='post' action='" + Encode.forHtmlAttribute(acUrl) + "'>");
            out.append("<p>");
            out.append("<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(loginResponse.getRespString()) + "'>");

            if(relayState != null) {
                out.append("<input type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState) + "'>");
            }

            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
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
