/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.query.saml.validation;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestUtil;

import java.util.List;

/**
 * This class is used to validate common elements for all the request types such as
 * signature, SAML version, issuer and etc
 */
public class AbstractSAMLQueryValidator implements SAMLQueryValidator {
    /**
     * Standard log
     */
    private static final Log log = LogFactory.getLog(AbstractSAMLQueryValidator.class);
    /**
     * Issuer instance holder
     */
    private SAMLSSOServiceProviderDO ssoIdpConfig = null;

    /**
     * Constructor with no arguments
     */
    public AbstractSAMLQueryValidator() {

    }

    /**
     * This method is used to validate issuer, signature and SAML version
     *
     * @param invalidItems List of invalid items tracked by validation process
     * @param request      Any type of assertion request
     * @return Boolean true if request is completely validated
     * @throws  IdentitySAML2QueryException If unable to validate request message elements
     */
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request)
            throws IdentitySAML2QueryException {

        boolean isIssuerValidated;
        boolean isSignatureValidated;
        boolean isValidSAMLVersion;
        boolean isRequestQueryProfileEnabled;

        try {
            //validate SAML Request vertion
            isValidSAMLVersion = this.validateSAMLVersion(request);
            if (isValidSAMLVersion) {
                //validate Issuer of Request
                isIssuerValidated = this.validateIssuer(request);
            } else {
                //invalid SAML version
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_VERSION,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_VERSION_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_VERSION_ERROR);
                return false;
            }
            if (isIssuerValidated) {
                // Check Assertion Query/Request Profile is enabled
                isRequestQueryProfileEnabled = ssoIdpConfig.isAssertionQueryRequestProfileEnabled();
            } else {
                //invalid issuer
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_ISSUER,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_ISSUER_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_ISSUER_ERROR);
                return false;
            }
            if (isRequestQueryProfileEnabled) {
                //validate Signature of Request
                isSignatureValidated = this.validateSignature(request);
            } else {
                //Assertion Query/Request Profile is not enabled
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_PROFILE_ENABLED,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_PROFILE_ENABLED_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_PROFILE_ENABLED_ERROR);
                return false;
            }
            if (!isSignatureValidated) {
                //invalid signature
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SIGNATURE,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_SIGNATURE_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_SIGNATURE_ERROR);
            }
        } catch (IdentitySAML2QueryException e) {
            log.error(SAMLQueryRequestConstants.ServiceMessages.SERVER_ERROR_PROCESSING_ISSUER_SIG_VERSION);
            throw new IdentitySAML2QueryException("Internal error while validating request signature", e);
        }
        return isSignatureValidated;
    }

    /**
     * This method is used to validate signature
     *
     * @param request any type of assertion request message
     * @return Boolean true, if signature is validated
     * @throws  IdentitySAML2QueryException If unable to validate signature
     */
    protected boolean validateSignature(RequestAbstractType request) throws IdentitySAML2QueryException {
        String alias;
        boolean isValidSig;
        String domainName;
        alias = ssoIdpConfig.getCertAlias();
        domainName = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            isValidSig = OpenSAML3Util.validateXMLSignature(request, alias, domainName);
            if (isValidSig) {
                log.debug("Request with id" + request.getID() + " contain valid signature");
                return true;

            } else {
                log.debug("Request with id:" + request.getID() + " contain in-valid Signature");
                return false;
            }

        } catch (IdentityException e) {
            log.error(SAMLQueryRequestConstants.ServiceMessages.SIGNATURE_VALIDATION_FAILED);
            throw new IdentitySAML2QueryException("Unable to validate signature of request with id:" + request.getID(), e);
        }
    }

    /**
     * This method is used to validate issuer of the request message
     *
     * @param request any type of request message
     * @return Boolean true, if issuer is valid
     * @throws IdentitySAML2QueryException If unable to collect issuer information
     */
    protected boolean validateIssuer(RequestAbstractType request) throws IdentitySAML2QueryException {
        //get full qualified issuer
        Issuer issuer = request.getIssuer();
        if (issuer.getValue() == null) {
            throw new IdentitySAML2QueryException("Issuer value is empty. Unable to validate issuer");
        } else {
            if (SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT.equals(issuer.getFormat())) {
                    ssoIdpConfig = SAMLQueryRequestUtil.getServiceProviderConfig(issuer.getValue());
                    if (ssoIdpConfig == null) {
                        log.error(SAMLQueryRequestConstants.ServiceMessages.NULL_ISSUER);
                        return false;
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug(SAMLQueryRequestConstants.ServiceMessages.SUCCESS_ISSUER + ssoIdpConfig.getIssuer());
                        }
                        return true;
                    }
            } else {
                log.error("NameID format is invalid in request ID:" + request.getID() + " and issuer: " + issuer.getValue());
                return false;
            }
        }
    }

    /**
     * This method is used to validate SAML version of request message
     *
     * @param request any type of request message
     * @return Boolean true, if SAML version is 2.0
     * @throws IdentitySAML2QueryException if SAML version not compatible
     */
    protected boolean validateSAMLVersion(RequestAbstractType request) throws IdentitySAML2QueryException {
        boolean isValidversion = false;
        if (request.getVersion() != null && request.getVersion().equals(SAMLVersion.VERSION_20)) {
            isValidversion = true;
        } else {
            log.error(SAMLQueryRequestConstants.ServiceMessages.NON_COMPAT_SAML_VERSION);
           // throw new IdentitySAML2QueryException("Request contain empty SAML version or non 2.0 version");
        }
        return isValidversion;
    }

    /**
     * This getter method return issuer information instance
     *
     * @return SAMLSSOServiceProviderDO issuer information
     */
    public SAMLSSOServiceProviderDO getSsoIdpConfig() {

        return ssoIdpConfig;
    }


}
