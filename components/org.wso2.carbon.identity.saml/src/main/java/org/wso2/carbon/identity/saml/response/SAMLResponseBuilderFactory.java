/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.SAML2SSORedirectRequestResponseBuilderFactory
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
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;
import org.wso2.carbon.identity.gateway.common.util.Utils;
import org.wso2.carbon.identity.saml.model.SAMLConfigurations;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class SAMLResponseBuilderFactory extends GatewayResponseBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAMLResponseBuilderFactory.class);

    @Override
    public boolean canHandle(GatewayResponse gatewayResponse) {
        if (gatewayResponse instanceof SAMLLoginResponse || gatewayResponse instanceof SAMLErrorResponse) {
            return true;
        }
        return false;
    }


    public Response.ResponseBuilder createBuilder(GatewayResponse gatewayResponse) {
        Response.ResponseBuilder builder = Response.noContent();
        createBuilder(builder, gatewayResponse);
        return builder;
    }

    public void createBuilder(Response.ResponseBuilder builder, GatewayResponse gatewayResponse) {
        super.createBuilder(builder, gatewayResponse);
        if (gatewayResponse instanceof SAMLLoginResponse) {
            sendResponse(builder, gatewayResponse);
        } else {
            sendNotification(builder, gatewayResponse);
        }
    }

    @Override
    public String getName() {
        return "SAMLResponseBuilderFactory";
    }

    @Override
    public int getPriority() {
        return 31;
    }

    private void sendResponse(Response.ResponseBuilder builder, GatewayResponse
            gatewayResponse) {

        SAMLLoginResponse loginResponse = ((SAMLLoginResponse) gatewayResponse);

        String authenticatedIdPs = loginResponse.getAuthenticatedIdPs();
        String relayState = loginResponse.getRelayState();
        String acUrl = loginResponse.getAcsUrl();

        //builder.status(Response.Status.TEMPORARY_REDIRECT).location(new URI(acUrl));
        builder.type(MediaType.TEXT_HTML);

        if (SAMLConfigurations.getInstance().getSsoResponseHtml() != null) {
            builder.entity(getRedirectHtml(acUrl, relayState, authenticatedIdPs, loginResponse));
        } else {
            builder.entity(getPostHtml(acUrl, relayState, authenticatedIdPs, loginResponse));
        }
        builder.status(200);
    }

    private String getRedirectHtml(String acUrl, String relayState, String authenticatedIdPs, SAMLLoginResponse
            loginResponse) {
        String finalPage = null;
        String htmlPage = SAMLConfigurations.getInstance().getSsoResponseHtml();
        String pageWithAcs = htmlPage.replace("$acUrl", acUrl);
        String pageWithAcsResponse = pageWithAcs.replace("<!--$params-->", "<!--$params-->\n" + "<input " +
                                                                           "type='hidden' name='SAMLResponse' value='"
                                                                           + Encode.forHtmlAttribute(
                loginResponse.getRespString
                        ()) + "'>");
        String pageWithAcsResponseRelay = pageWithAcsResponse;

        if (relayState != null) {
            pageWithAcsResponseRelay = pageWithAcsResponse.replace("<!--$params-->", "<!--$params-->\n" + "<input" +
                                                                                     " type='hidden' "
                                                                                     + "name='RelayState' value='"
                                                                                     + Encode.forHtmlAttribute(
                    relayState) + "'>");
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
                                                                                                        .getRespString())
                   + "'>");

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

    private void sendNotification(Response.ResponseBuilder builder, GatewayResponse
            gatewayResponse) {
        try {
            SAMLErrorResponse errorResponse = ((SAMLErrorResponse) gatewayResponse);
            String redirectURL = SAMLSSOUtil.getNotificationEndpoint();
            Map<String, String[]> queryParams = new HashMap();

            //TODO Send status codes rather than full messages in the GET request
            try {
                queryParams.put(SAMLSSOConstants.STATUS, new String[] { URLEncoder.encode(errorResponse.getStatus(),
                                                                                          StandardCharsets.UTF_8
                                                                                                  .name()) });
                queryParams
                        .put(SAMLSSOConstants.STATUS_MSG, new String[] { URLEncoder.encode(errorResponse.getMessageLog()
                                , StandardCharsets.UTF_8.name()) });

                if (StringUtils.isNotEmpty(errorResponse.getErrorResponse())) {
                    queryParams.put(SAMLSSOConstants.SAML_RESP, new String[] { URLEncoder.encode(errorResponse
                                                                                                         .getErrorResponse(),
                                                                                                 StandardCharsets.UTF_8
                                                                                                         .name()) });
                }

                if (StringUtils.isNotEmpty(errorResponse.getAcsUrl())) {
                    queryParams.put(SAMLSSOConstants.ASSRTN_CONSUMER_URL, new String[] { URLEncoder.encode(errorResponse
                                                                                                                   .getAcsUrl(),
                                                                                                           StandardCharsets.UTF_8
                                                                                                                   .name()) });
                }
            } catch (UnsupportedEncodingException e) {

            }
            builder.status(302);
            //builder.setParameters(queryParams);
            String httpQueryString = Utils.buildQueryString(queryParams);
            if (redirectURL.indexOf("?") > -1) {
                redirectURL = redirectURL.concat("&").concat(httpQueryString.toString());
            } else {
                redirectURL = redirectURL.concat("?").concat(httpQueryString.toString());
            }
            builder.location(new URI(redirectURL));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }
}
