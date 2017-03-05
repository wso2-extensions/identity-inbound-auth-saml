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
package org.wso2.carbon.identity.saml.validator;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.common.base.message.MessageContext;
import org.wso2.carbon.identity.gateway.api.context.GatewayMessageContext;
import org.wso2.carbon.identity.gateway.common.model.sp.RequestValidatorConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.api.response.GatewayHandlerResponse;
import org.wso2.carbon.identity.gateway.exception.RequestValidatorException;
import org.wso2.carbon.identity.saml.util.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAMLClientException;
import org.wso2.carbon.identity.saml.exception.SAMLRequestValidatorException;
import org.wso2.carbon.identity.saml.request.SAMLIDPInitRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.saml.model.SAMLValidatorConfig;

import java.io.IOException;

public class IDPInitSAMLValidator extends SAMLValidator {

    private static Logger log = LoggerFactory.getLogger(IDPInitSAMLValidator.class);

    @Override
    public boolean canHandle(MessageContext messageContext) {
        if (messageContext instanceof GatewayMessageContext) {
            GatewayMessageContext gatewayMessageContext = (GatewayMessageContext) messageContext;
            if (gatewayMessageContext.getIdentityRequest() instanceof SAMLIDPInitRequest) {
                return true;
            }
            return false;
        }
        return false;
    }

    public String getName() {
        return "IDPInitSAMLValidator";
    }

    public int getPriority(MessageContext messageContext) {
        return 11;
    }

    @Override
    public GatewayHandlerResponse validate(AuthenticationContext authenticationContext) throws SAMLRequestValidatorException{
        try {
            initSAMLMessageContext(authenticationContext);
            SAMLMessageContext messageContext = (SAMLMessageContext) authenticationContext
                    .getParameter(SAMLSSOConstants.SAMLContext);
            String spEntityID = ((SAMLIDPInitRequest) messageContext.getIdentityRequest()).getSpEntityID();
            authenticationContext.setUniqueId(spEntityID);

            RequestValidatorConfig validatorConfig = getValidatorConfig(authenticationContext);
            updateValidatorConfig(validatorConfig, authenticationContext);

            if (validateEntity(messageContext)) {
                SAMLValidatorConfig samlValidatorConfig = messageContext.getSamlValidatorConfig();

                if (samlValidatorConfig == null) {
                    String msg = "A Service Provider with the Issuer '" + messageContext.getIssuer() + "' is not " +
                                 "registered." + " Service Provider should be registered in advance.";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    throw new RequestValidatorException(msg);
                }

                if (!samlValidatorConfig.isIdPInitSSOEnabled()) {
                    String msg = "IdP initiated SSO not enabled for service provider '" + messageContext.getIssuer()
                                 + "'.";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    throw new RequestValidatorException(msg);
                }

                if (samlValidatorConfig.isEnableAttributesByDefault() && samlValidatorConfig
                                                                                 .getAttributeConsumingServiceIndex()
                                                                         != null) {
                    messageContext.setAttributeConsumingServiceIndex(Integer.parseInt(samlValidatorConfig
                                                                                              .getAttributeConsumingServiceIndex()));
                }


                String acsUrl = StringUtils.isNotBlank(
                        ((SAMLIDPInitRequest) messageContext.getIdentityRequest()).getAcs()) ? (
                                        (SAMLIDPInitRequest) messageContext.getIdentityRequest())
                                        .getAcs() : samlValidatorConfig
                                        .getDefaultAssertionConsumerUrl();
                if (StringUtils.isBlank(acsUrl) || !samlValidatorConfig.getAssertionConsumerUrlList().contains
                        (acsUrl)) {
                    String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                                 "AuthnRequest message from  the issuer '" + samlValidatorConfig.getIssuer() +
                                 "'. Possibly " + "an attempt for a spoofing attack";
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    throw new RequestValidatorException(msg);
                }
                return GatewayHandlerResponse.CONTINUE;
            }
        } catch (IdentityException e) {
            throw new SAMLRequestValidatorException("Error while validating SAML request");
        } catch (IOException e) {
            throw new SAMLRequestValidatorException("Error while validating SAML request");
        }

        throw new SAMLRequestValidatorException("Error while validating SAML request");
    }


    /**
     * Validates the authentication request according to IdP Initiated SAML SSO Web Browser Specification
     *
     * @return SAMLSSOSignInResponseDTO
     * @throws
     */
    public boolean validateEntity(SAMLMessageContext messageContext) throws
                                                                     IdentityException, IOException {


        // spEntityID MUST NOT be null
        String spEntityID = ((SAMLIDPInitRequest) messageContext.getIdentityRequest()).getSpEntityID();
        if (StringUtils.isNotBlank(spEntityID)) {
            messageContext.setIssuer(spEntityID);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("spEntityID parameter not found in request");
            }
            messageContext.setValid(false);
            throw SAMLClientException.error(SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                                    .REQUESTOR_ERROR,
                                                                           "spEntityID parameter not found in request",
                                                                           null));
        }

        if (!SAMLSSOUtil.isSAMLIssuerExists(spEntityID)) {
            String message = "A Service Provider with the Issuer '" + spEntityID + "' is not registered. Service " +
                             "Provider should be registered in advance";
            String errorResp = SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                                                              message, null);
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            messageContext.setValid(false);
            throw SAMLClientException.error(SAMLSSOUtil.SAMLResponseUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                                                                                   .REQUESTOR_ERROR, message, null));
        }

        messageContext.setValid(true);

        if (log.isDebugEnabled()) {
            log.debug("IdP Initiated SSO request validation is successful");
        }
        return true;
    }
}
