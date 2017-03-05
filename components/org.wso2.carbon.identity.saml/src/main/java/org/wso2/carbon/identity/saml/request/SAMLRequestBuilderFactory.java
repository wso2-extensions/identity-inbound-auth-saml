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

package org.wso2.carbon.identity.saml.request;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequest;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequestBuilderFactory;
import org.wso2.carbon.identity.gateway.common.util.Utils;
import org.wso2.carbon.identity.gateway.processor.util.Utility;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.exception.SAMLClientException;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.msf4j.Request;

import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * SAMLRequestBuilderFactory is the factory that is build the SAML request.
 */
public class SAMLRequestBuilderFactory extends GatewayRequestBuilderFactory {

    private static Logger log = LoggerFactory.getLogger(SAMLRequestBuilderFactory.class);

    @Override
    public boolean canHandle(Request request) throws GatewayClientException {
        String samlRequest = Utility.getParameter(request, SAMLSSOConstants.SAML_REQUEST);
        String spEntityID = Utility.getParameter(request, SAMLSSOConstants.QueryParameter.SP_ENTITY_ID.toString());
        if (StringUtils.isNotBlank(samlRequest) || StringUtils.isNotBlank(spEntityID)) {
            return true;
        }
        return false;
    }

    @Override
    public GatewayRequest.GatewayRequestBuilder create(Request request) throws GatewayClientException {

        String spEntityID = Utility.getParameter(request, SAMLSSOConstants.QueryParameter.SP_ENTITY_ID.toString());
        GatewayRequest.GatewayRequestBuilder builder = null;

        if (spEntityID != null) {
            builder = new SAMLIDPInitRequest.SAMLIdpInitRequestBuilder();
        } else {
            builder = new SAMLSPInitRequest.SAMLSpInitRequestBuilder();
        }
        super.create(builder, request);
        return builder;
    }

    @Override
    public String getName() {
        return "SAMLRequestBuilderFactory";
    }

    @Override
    public int getPriority() {
        return 30;
    }

    public Response.ResponseBuilder handleException(GatewayClientException exception) {

        javax.ws.rs.core.Response.ResponseBuilder builder = javax.ws.rs.core.Response.noContent();
        String redirectURL = SAMLSSOUtil.getNotificationEndpoint();
        Map<String, String[]> queryParams = new HashMap();
        //TODO Send status codes rather than full messages in the GET request
        try {
            queryParams.put(SAMLSSOConstants.STATUS, new String[] { URLEncoder.encode(((SAMLClientException)
                    exception).getExceptionStatus(), StandardCharsets.UTF_8.name()) });
            queryParams.put(SAMLSSOConstants.STATUS_MSG, new String[] { URLEncoder.encode(((SAMLClientException)
                    exception).getExceptionMessage(), StandardCharsets.UTF_8.name()) });
            if (exception.getMessage() != null) {
                queryParams.put(SAMLSSOConstants.SAML_RESP, new String[] { URLEncoder.encode(exception.getMessage()
                        , StandardCharsets.UTF_8.name()) });
            }
            if (((SAMLClientException) exception).getACSUrl() != null) {
                queryParams.put(SAMLSSOConstants.ASSRTN_CONSUMER_URL, new String[] { URLEncoder.encode((
                                                                                                               (SAMLClientException) exception)
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

        String httpQueryString = Utils.buildQueryString(queryParams);
        if (redirectURL.indexOf("?") > -1) {
            redirectURL = redirectURL.concat("&").concat(httpQueryString.toString());
        } else {
            redirectURL = redirectURL.concat("?").concat(httpQueryString.toString());
        }
        try {
            builder.location(new URI(redirectURL));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        builder.status(301);
        return builder;
    }
}
