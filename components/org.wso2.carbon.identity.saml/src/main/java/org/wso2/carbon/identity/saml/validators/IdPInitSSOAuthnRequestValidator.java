/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.saml.validators;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.AuthnRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.common.base.exception.IdentityException;
import org.wso2.carbon.identity.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.saml.context.SAMLMessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2ClientException;
import org.wso2.carbon.identity.saml.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import java.io.IOException;


public class IdPInitSSOAuthnRequestValidator {

    private static Logger log = LoggerFactory.getLogger(IdPInitSSOAuthnRequestValidator.class);

    private SAMLMessageContext messageContext;
    private String spEntityID;


    public IdPInitSSOAuthnRequestValidator(SAMLMessageContext messageContext) throws IdentityException {
        this.messageContext = messageContext;
        this.spEntityID = ((SAMLIdpInitRequest) messageContext.getIdentityRequest()).getSpEntityID();
    }

    /**
     * Validates the authentication request according to IdP Initiated SAML SSO Web Browser Specification
     *
     * @return SAMLSSOSignInResponseDTO
     * @throws
     */
    public boolean validate(AuthnRequest authnRequest) throws IdentityException, IOException {


        // spEntityID MUST NOT be null
        if (StringUtils.isNotBlank(spEntityID)) {
            this.messageContext.setIssuer(spEntityID);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("spEntityID parameter not found in request");
            }
            messageContext.setValid(false);
            throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                    "spEntityID parameter not found in request", null));
        }

        if (!SAMLSSOUtil.isSAMLIssuerExists(spEntityID, SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
            String message = "A Service Provider with the Issuer '" + spEntityID + "' is not registered. Service " +
                    "Provider should be registered in advance";
            String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                    message, null);
            if (log.isDebugEnabled()) {
                log.debug(message);
            }
            messageContext.setValid(false);
            throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                    .REQUESTOR_ERROR, message, null));
        }

        messageContext.setValid(true);

        if (log.isDebugEnabled()) {
            log.debug("IdP Initiated SSO request validation is successful");
        }
        return true;
    }

}
