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
import org.wso2.carbon.identity.sso.samlnew.bean.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.samlnew.internal.IdentitySAMLSSOServiceComponent;

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
        AuthenticationResult authnResult = (AuthenticationResult)messageContext.getParameter("AuthenticationResult");
        AuthnRequest authnRequest = messageContext.getAuthnRequest();
        HttpIdentityResponse.HttpIdentityResponseBuilder builder = new HttpIdentityResponse.HttpIdentityResponseBuilder();
        if (IdentitySAMLSSOServiceComponent.getSsoRedirectHtml() != null) {

            String finalPage = null;
            String htmlPage = IdentitySAMLSSOServiceComponent.getSsoRedirectHtml();
            String pageWithAcs = htmlPage.replace("$acUrl", authnRequest.getAssertionConsumerServiceURL());
            String pageWithAcsResponse = pageWithAcs.replace("<!--$params-->", "<!--$params-->\n" + "<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(loginResponse.getRespString()) + "'>");
            String pageWithAcsResponseRelay = pageWithAcsResponse;
            String relayState = messageContext.getRelayState();
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

            if (log.isDebugEnabled()) {
                log.debug("samlsso_response.html " + finalPage);
            }


        } else {
//            PrintWriter out = resp.getWriter();
//            out.println("<html>");
//            out.println("<body>");
//            out.println("<p>You are now redirected back to " + Encode.forHtmlContent(acUrl));
//            out.println(" If the redirection fails, please click the post button.</p>");
//            out.println("<form method='post' action='" + Encode.forHtmlAttribute(acUrl) + "'>");
//            out.println("<p>");
//            out.println("<input type='hidden' name='SAMLResponse' value='" + Encode.forHtmlAttribute(response) + "'>");
//
//            if(relayState != null) {
//                out.println("<input type='hidden' name='RelayState' value='" + Encode.forHtmlAttribute(relayState) + "'>");
//            }
//
//            if (authenticatedIdPs != null && !authenticatedIdPs.isEmpty()) {
//                out.println("<input type='hidden' name='AuthenticatedIdPs' value='" +
//                        Encode.forHtmlAttribute(authenticatedIdPs) + "'>");
//            }
//
//            out.println("<button type='submit'>POST</button>");
//            out.println("</p>");
//            out.println("</form>");
//            out.println("<script type='text/javascript'>");
//            out.println("document.forms[0].submit();");
//            out.println("</script>");
//            out.println("</body>");
//            out.println("</html>");
        }
//        builder.setStatusCode(response.getResponseStatus());
//        builder.setHeaders(response.getHeaders());
//        builder.addHeader(OAuth2.Header.CACHE_CONTROL,
//                OAuth2.HeaderValue.CACHE_CONTROL_NO_STORE);
//        builder.addHeader(OAuth2.Header.PRAGMA,
//                OAuth2.HeaderValue.PRAGMA_NO_CACHE);
        builder.setBody("");
        return builder;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(HttpIdentityResponse.HttpIdentityResponseBuilder
                                                                               httpIdentityResponseBuilder, IdentityResponse identityResponse) {
        return null;
    }
}
