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
    private final static Log log = LogFactory.getLog(AbstractSAMLQueryValidator.class);
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
     */
    public boolean validate(List<InvalidItemDTO> invalidItems, RequestAbstractType request) {

        boolean isIssuerValidated;
        boolean isSignatureValidated;
        boolean isValidSAMLVersion;

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
                //validate Signature of Request
                isSignatureValidated = this.validateSignature(request);
            } else {
                //invalid issuer
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_ISSUER,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_ISSUER_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_ISSUER_ERROR);
                return false;
            }
            if (!isSignatureValidated) {
                //invalid signature
                invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SIGNATURE,
                        SAMLQueryRequestConstants.ValidationMessage.VAL_SIGNATURE_ERROR));
                log.error(SAMLQueryRequestConstants.ValidationMessage.VAL_SIGNATURE_ERROR);
            }
        } catch (IdentityException ex) {
            log.error(SAMLQueryRequestConstants.ServiceMessages.SERVER_ERROR_PROCESSING_ISSUER_SIG_VERSION);
            return false;
        }
        return isSignatureValidated;
    }

    /**
     * This method is used to validate signature
     *
     * @param request any type of assertion request message
     * @return Boolean true, if signature is validated
     */
    protected boolean validateSignature(RequestAbstractType request) {
        String alias;
        boolean isValidSig;
        String domainName;
        alias = ssoIdpConfig.getCertAlias();
        domainName = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {

            isValidSig = OpenSAML3Util.validateXMLSignature(request,
                    alias, domainName);

            if (isValidSig) {
                log.debug("Signature successfully validated");
                return true;

            } else {
                log.debug("In valid Signature");
                return false;
            }

        } catch (IdentityException ex) {
            log.error(SAMLQueryRequestConstants.ServiceMessages.SIGNATURE_VALIDATION_FAILED);
            log.error(ex.getMessage());
        }
        return false;
    }

    /**
     * This method is used to validate issuer of the request message
     *
     * @param request any type of request message
     * @return Boolean true, if issuer is valid
     * @throws IdentityException If unable to collect issuer information
     */
    protected boolean validateIssuer(RequestAbstractType request) throws IdentityException {
        Issuer issuer = request.getIssuer();
        boolean validIssuer = false;
        String IssuerSPProvidedID;
        String IssuerName;
        if (issuer.getValue() == null && issuer.getSPProvidedID() == null) {

            throw IdentityException.error(SAMLQueryRequestConstants.ValidationMessage.EXIT_WITH_ERROR);
        } else {
            if (issuer.getFormat() != null) {
                if (issuer.getFormat().equals(SAMLQueryRequestConstants.GenericConstants.ISSUER_FORMAT)) {

                    try {
                        ssoIdpConfig = SAMLQueryRequestUtil.getServiceProviderConfig(issuer.getValue());
                        if (ssoIdpConfig == null) {
                            log.error(SAMLQueryRequestConstants.ServiceMessages.NULL_ISSUER);
                            return validIssuer;
                        } else {
                            log.debug(SAMLQueryRequestConstants.ServiceMessages.SUCCESS_ISSUER + ssoIdpConfig.getIssuer());
                            validIssuer = true;
                        }
                    } catch (IdentityException e) {
                        log.error(SAMLQueryRequestConstants.ServiceMessages.ISSUER_VALIDATION_FAILED);
                        log.error("Unable to load Service Provider info", e);
                    }

                } else {

                    log.error(SAMLQueryRequestConstants.ServiceMessages.NO_ISSUER_PRESENTED);
                    throw IdentityException.error(
                            SAMLQueryRequestConstants.ValidationMessage.EXIT_WITH_ERROR);
                }

            }

        }


        return validIssuer;
    }

    /**
     * This method is used to validate SAML version of request message
     *
     * @param request any type of request message
     * @return Boolean true, if SAML version is 2.0
     * @throws IdentityException if SAML version not compatible
     */
    protected boolean validateSAMLVersion(RequestAbstractType request) throws IdentityException {
        boolean isValidversion = false;
        if (request.getVersion().equals(SAMLVersion.VERSION_20)) {
            isValidversion = true;
        } else {
            log.error(SAMLQueryRequestConstants.ServiceMessages.NON_COMPAT_SAML_VERSION);
            throw IdentityException.error(SAMLQueryRequestConstants.ValidationMessage.EXIT_WITH_ERROR);

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
