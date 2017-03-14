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

package org.wso2.carbon.identity.saml.request;

import com.google.common.net.HttpHeaders;
import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequest;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequestBuilderFactory;
import org.wso2.carbon.identity.gateway.util.GatewayUtil;
import org.wso2.carbon.identity.saml.exception.SAML2SSOClientException;
import org.wso2.carbon.identity.saml.model.Config;
import org.wso2.carbon.identity.saml.util.Utils;
import org.wso2.msf4j.Request;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.core.Response;

/**
 * The factory responsible of building the SAML2SSORequest sent by service provider.
 */
public class SAML2SSORequestBuilderFactory extends GatewayRequestBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAML2SSORequestBuilderFactory.class);

    @Override
    public boolean canHandle(Request request) throws GatewayClientException {
        String samlRequest = GatewayUtil.getParameter(request, SAML2AuthConstants.SAML_REQUEST);
        String spEntityID = GatewayUtil.getParameter(request, SAML2AuthConstants.SP_ENTITY_ID.toString());
        if (StringUtils.isNotBlank(samlRequest) || StringUtils.isNotBlank(spEntityID)) {
            return true;
        }
        return false;
    }

    @Override
    public GatewayRequest.GatewayRequestBuilder create(Request request) throws GatewayClientException {

        String spEntityID = GatewayUtil.getParameter(request, SAML2AuthConstants.SP_ENTITY_ID.toString());
        GatewayRequest.GatewayRequestBuilder builder = null;

        if (spEntityID != null) {
            builder = new IdPInitRequest.SAMLIdpInitRequestBuilder();
        } else {
            builder = new SPInitRequest.SAMLSpInitRequestBuilder();
        }
        super.create(builder, request);
        return builder;
    }

    @Override
    public int getPriority() {
        return 75;
    }

    public Response.ResponseBuilder handleException(GatewayClientException exception) {

        javax.ws.rs.core.Response.ResponseBuilder builder = javax.ws.rs.core.Response.noContent();
        String redirectURL = Config.getInstance().getErrorPageUrl();
        Map<String, String[]> queryParams = new HashMap();
        //TODO Send status codes rather than full messages in the GET request
        try {
            queryParams.put(Status.DEFAULT_ELEMENT_LOCAL_NAME, new String[] {URLEncoder.encode(((SAML2SSOClientException)
                    exception).getErrorCode(), StandardCharsets.UTF_8.name()) });
            queryParams.put(StatusMessage.DEFAULT_ELEMENT_LOCAL_NAME, new String[] {URLEncoder.encode(((SAML2SSOClientException)
                    exception).getErrorCode(), StandardCharsets.UTF_8.name()) });
            if (exception.getMessage() != null) {
                queryParams.put(SAML2AuthConstants.SAML_RESPONSE, new String[] {URLEncoder.encode(exception.getMessage()
                        , StandardCharsets.UTF_8.name()) });
            }
            if (((SAML2SSOClientException) exception).getACSUrl() != null) {
                queryParams.put(SAML2AuthConstants.ASSRTN_CONSUMER_URL, new String[] {URLEncoder.encode((
                                                                                                               (SAML2SSOClientException) exception)
                                                                                                               .getACSUrl(),
                                                                                               StandardCharsets.UTF_8
                                                                                                               .name()) });
            }
            //builder.setParameters(queryParams);
        } catch (UnsupportedEncodingException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding query parameters.", e);
            }
        }

        String httpQueryString = GatewayUtil.buildQueryString(queryParams);
        if (redirectURL.indexOf("?") > -1) {
            redirectURL = redirectURL.concat("&").concat(httpQueryString.toString());
        } else {
            redirectURL = redirectURL.concat("?").concat(httpQueryString.toString());
        }

        builder.header(HttpHeaders.LOCATION, redirectURL);
        builder.status(301);
        return builder;
    }
}
