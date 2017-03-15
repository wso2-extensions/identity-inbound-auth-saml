/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.saml.response;

import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponse;
import org.wso2.carbon.identity.gateway.api.response.GatewayResponseBuilderFactory;
import org.wso2.carbon.identity.saml.model.Config;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class SAML2SSOResponseBuilderFactory extends GatewayResponseBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAML2SSOResponseBuilderFactory.class);

    @Override
    public boolean canHandle(GatewayResponse gatewayResponse) {
        if (gatewayResponse instanceof SAML2SSOResponse) {
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
        sendResponse(builder, (SAML2SSOResponse) gatewayResponse);

    }

    @Override
    public int getPriority() {
        return 31;
    }

    private void sendResponse(Response.ResponseBuilder builder, SAML2SSOResponse saml2SSOResponse) {

        String relayState = saml2SSOResponse.getRelayState();
        String acUrl = saml2SSOResponse.getAcsUrl();

        //builder.status(Response.Status.TEMPORARY_REDIRECT).location(new URI(acUrl));
        builder.type(MediaType.TEXT_HTML);

        builder.entity(getRedirectHtml(acUrl, relayState, saml2SSOResponse));

        builder.status(200);
    }

    private String getRedirectHtml(String acUrl, String relayState, SAML2SSOResponse saml2SSOResponse) {

        String htmlPage = Config.getInstance().getSsoResponseHtml();
        String pageWithAcs = htmlPage.replace("$acUrl", acUrl);
        String pageWithAcsResponse = pageWithAcs.replace("<!--$params-->", "<!--$params-->\n" + "<input " +
                                                                           "type='hidden' name='SAMLResponse' value='"
                                                                           + Encode.forHtmlAttribute(
                saml2SSOResponse.getRespString
                        ()) + "'>");
        String pageWithAcsResponseRelay = pageWithAcsResponse;

        if (relayState != null) {
            pageWithAcsResponseRelay = pageWithAcsResponse.replace("<!--$params-->", "<!--$params-->\n" + "<input" +
                                                                                     " type='hidden' "
                                                                                     + "name='RelayState' value='"
                                                                                     + Encode.forHtmlAttribute(
                    relayState) + "'>");
        }

        if (log.isDebugEnabled()) {
            log.debug("samlsso_response.html " + pageWithAcsResponseRelay);
        }
        return pageWithAcsResponseRelay;
    }
}
