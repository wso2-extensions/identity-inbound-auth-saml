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

package org.wso2.carbon.identity.saml.validator;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.StatusCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.gateway.api.exception.GatewayClientException;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.handler.GatewayHandlerResponse;
import org.wso2.carbon.identity.saml.bean.SAML2SSOContext;
import org.wso2.carbon.identity.saml.exception.InvalidSPEntityIdException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORequestValidationException;
import org.wso2.carbon.identity.saml.model.Config;
import org.wso2.carbon.identity.saml.model.RequestValidatorConfig;
import org.wso2.carbon.identity.saml.request.IdPInitRequest;

/**
 * IdP Initiated SAML2 SSO Inbound Request Validator.
 */
public class IdPInitValidator extends SAML2SSOValidator {

    private static Logger logger = LoggerFactory.getLogger(IdPInitValidator.class);

    @Override
    public boolean canHandle(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        if (messageContext instanceof AuthenticationContext) {
            AuthenticationContext authenticationContext = (AuthenticationContext) messageContext;
            if (authenticationContext.getInitialAuthenticationRequest() instanceof IdPInitRequest) {
                return true;
            }
        }
        return false;
    }

    public int getPriority(org.wso2.carbon.identity.common.base.message.MessageContext messageContext) {
        return 11;
    }

    protected SAML2SSOContext createInboundMessageContext(AuthenticationContext authenticationContext)
            throws SAML2SSORequestValidationException {

        SAML2SSOContext saml2SSOContext = super.createInboundMessageContext(authenticationContext);
        String spEntityId = ((IdPInitRequest) saml2SSOContext.getRequest()).getSPEntityId();
        try {
            authenticationContext.setServiceProviderId(spEntityId);
        } catch (GatewayClientException e) {
            InvalidSPEntityIdException ex =
                    new InvalidSPEntityIdException(StatusCode.REQUESTER_URI, e.getMessage());
            ex.setAcsUrl(Config.getInstance().getErrorPageUrl());
            throw ex;
        }
        saml2SSOContext.setName(authenticationContext.getServiceProvider().getName());

        org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig validatorConfig =
                getValidatorConfig(authenticationContext);
        RequestValidatorConfig requestValidatorConfig = new RequestValidatorConfig(validatorConfig);
        saml2SSOContext.setRequestValidatorConfig(requestValidatorConfig);
        return saml2SSOContext;
    }

    @Override
    public GatewayHandlerResponse validate(AuthenticationContext authenticationContext)
            throws SAML2SSORequestValidationException {

        SAML2SSOContext saml2SSOContext = createInboundMessageContext(authenticationContext);
        RequestValidatorConfig requestValidatorConfig = saml2SSOContext.getRequestValidatorConfig();
        String spName = authenticationContext.getServiceProvider().getName();

        saml2SSOContext.setSPEntityId(authenticationContext.getServiceProviderId());

        String acs = ((IdPInitRequest) saml2SSOContext.getRequest()).getAcs();
        if (StringUtils.isNotBlank(acs)) {
            if (!requestValidatorConfig.getAssertionConsumerUrlList().contains(acs)) {
                SAML2SSORequestValidationException ex =
                        new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI,
                                                               "Invalid Assertion Consumer Service URL value '" + acs +
                                                               "' in the request from '" + spName + "'.");
                ex.setAcsUrl(Config.getInstance().getErrorPageUrl());
                throw ex;
            }
        } else {
            acs = requestValidatorConfig.getDefaultAssertionConsumerUrl();
        }
        saml2SSOContext.setAssertionConsumerUrl(acs);

        if (!requestValidatorConfig.isIdPInitSSOEnabled()) {
            SAML2SSORequestValidationException ex =
                    new SAML2SSORequestValidationException(StatusCode.REQUESTER_URI,
                                                           "IdP-initiated SSO not enabled for service provider '" +
                                                           spName + "'.");
            ex.setAcsUrl(saml2SSOContext.getAssertionConsumerURL());
            throw ex;
        }

        if (requestValidatorConfig.sendBackClaimsAlways() && requestValidatorConfig
                                                                     .getAttributeConsumingServiceIndex() != null) {
            saml2SSOContext.setAttributeConsumingServiceIndex(
                    Integer.parseInt(requestValidatorConfig.getAttributeConsumingServiceIndex()));
        }

        return new GatewayHandlerResponse();

    }
}
