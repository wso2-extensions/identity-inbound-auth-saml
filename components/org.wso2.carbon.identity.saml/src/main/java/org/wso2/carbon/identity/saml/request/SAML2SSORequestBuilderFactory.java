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

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequest;
import org.wso2.carbon.identity.gateway.api.request.GatewayRequestBuilderFactory;
import org.wso2.carbon.identity.gateway.util.GatewayUtil;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.msf4j.Request;

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
        // This method will never be reached.
        throw new SAML2SSORuntimeException(StatusCode.RESPONDER_URI, "Method not implemented.",
                                           new UnsupportedOperationException("Method not implemented."));
    }
}
