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
package org.wso2.carbon.identity.sso.saml.builders;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.extension.SAMLExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.security.NoSuchAlgorithmException;

public class DefaultResponseBuilder implements ResponseBuilder {

    private static Log log = LogFactory.getLog(DefaultResponseBuilder.class);

    static {
        SAMLSSOUtil.doBootstrap();
    }

    @Override
    public Response buildResponse(SAMLSSOAuthnReqDTO authReqDTO, String sessionId)
            throws IdentityException {

        if (log.isDebugEnabled()) {
            log.debug("Building SAML Response for the consumer '"
                    + authReqDTO.getAssertionConsumerURL() + "'");
        }

        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                + SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 * 1000L);

        Assertion assertion = SAMLSSOUtil.buildSAMLAssertion(authReqDTO, notOnOrAfter, sessionId);

        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        if (!authReqDTO.isIdPInitSSOEnabled()) {
            response.setInResponseTo(authReqDTO.getId());
        }
        response.setDestination(authReqDTO.getAssertionConsumerURL());
        response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssueInstant(issueInstant);

        for (SAMLExtensionProcessor extensionProcessor : SAMLSSOUtil.getExtensionProcessors()) {
            if (extensionProcessor.canHandle(response, assertion, authReqDTO)) {
                extensionProcessor.processSAMLExtensions(response, assertion, authReqDTO);
            }
        }

        if (authReqDTO.isDoEnableEncryptedAssertion()) {

            String domainName = authReqDTO.getTenantDomain();
            String alias = authReqDTO.getCertAlias();
            String assertionEncryptionAlgorithm = authReqDTO.getAssertionEncryptionAlgorithmUri();
            String keyEncryptionAlgorithm = authReqDTO.getKeyEncryptionAlgorithmUri();
            if (alias != null) {
                EncryptedAssertion encryptedAssertion = SAMLSSOUtil.setEncryptedAssertion(assertion,
                        assertionEncryptionAlgorithm, keyEncryptionAlgorithm, alias, domainName);
                response.getEncryptedAssertions().add(encryptedAssertion);
            } else {
                log.warn("Certificate alias is not found. Assertion is not encrypted and not included in response");
            }
        } else {
            response.getAssertions().add(assertion);
        }

        if (authReqDTO.isDoSignResponse()) {
            SAMLSSOUtil.setSignature(response, authReqDTO.getSigningAlgorithmUri(), authReqDTO.getDigestAlgorithmUri
                    (), new SignKeyDataHolder(authReqDTO.getUser().getAuthenticatedSubjectIdentifier()));
        }
        return response;
    }

    public Response buildResponse(SAMLSSOAuthnReqDTO authReqDTO, Assertion assertion)
            throws IdentityException {

        if (log.isDebugEnabled()) {
            log.debug("Building SAML Response for the consumer '"
                    + authReqDTO.getAssertionConsumerURL() + "'");
        }
        Response response = new org.opensaml.saml2.core.impl.ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        response.setInResponseTo(authReqDTO.getId());
        response.setDestination(authReqDTO.getAssertionConsumerURL());
        response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        response.setIssueInstant(issueInstant);
        response.getAssertions().add(assertion);
        if (authReqDTO.isDoSignResponse()) {
            SAMLSSOUtil.setSignature(response, authReqDTO.getSigningAlgorithmUri(), authReqDTO.getDigestAlgorithmUri
                    (), new SignKeyDataHolder(authReqDTO.getUser().getAuthenticatedSubjectIdentifier()));
        }
        return response;
    }

}
