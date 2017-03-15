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

package org.wso2.carbon.identity.saml.util;

import org.apache.commons.lang.StringUtils;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.gateway.common.model.sp.AuthenticationStepConfig;
import org.wso2.carbon.identity.gateway.context.AuthenticationContext;
import org.wso2.carbon.identity.gateway.context.SequenceContext;
import org.wso2.carbon.identity.mgt.claim.Claim;
import org.wso2.carbon.identity.saml.bean.MessageContext;
import org.wso2.carbon.identity.saml.exception.SAML2SSOResponseBuilderException;
import org.wso2.carbon.identity.saml.exception.SAML2SSORuntimeException;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.saml.internal.SAML2InboundAuthDataHolder;
import org.wso2.carbon.identity.saml.model.ResponseBuilderConfig;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Utilities needed for SAML2 SSO Inbound Authenticator.
 */
public class Utils {

    private static Logger logger = LoggerFactory.getLogger(Utils.class);

    public static Map<String, String> getAttributes(AuthenticationContext authenticationContext) {

        int index = 0;
        MessageContext messageContext = (MessageContext) authenticationContext
                .getParameter(SAML2AuthConstants.SAML_CONTEXT);

        ResponseBuilderConfig responseBuilderConfig = messageContext.getResponseBuilderConfig();
        if (!messageContext.isIdpInitSSO()) {

            if (messageContext.getAttributeConsumingServiceIndex() == 0) {
                //SP has not provide a AttributeConsumingServiceIndex in the authnReqDTO
                if (StringUtils.isNotBlank(responseBuilderConfig.getAttributeConsumingServiceIndex()) &&
                    responseBuilderConfig.sendBackClaimsAlways()) {
                    index = Integer.parseInt(responseBuilderConfig.getAttributeConsumingServiceIndex());
                } else {
                    return null;
                }
            } else {
                //SP has provide a AttributeConsumingServiceIndex in the authnReqDTO
                index = messageContext.getAttributeConsumingServiceIndex();
            }
        } else {
            if (StringUtils.isNotBlank(responseBuilderConfig.getAttributeConsumingServiceIndex()) &&
                responseBuilderConfig.sendBackClaimsAlways()) {
                index = Integer.parseInt(responseBuilderConfig.getAttributeConsumingServiceIndex());
            } else {
                return null;
            }
        }


		/*
         * IMPORTANT : checking if the consumer index in the request matches the
		 * given id to the SP
		 */
        if (responseBuilderConfig.getAttributeConsumingServiceIndex() == null ||
            "".equals(responseBuilderConfig.getAttributeConsumingServiceIndex()) ||
            index != Integer.parseInt(responseBuilderConfig.getAttributeConsumingServiceIndex())) {
            if (logger.isDebugEnabled()) {
                logger.debug("Invalid AttributeConsumingServiceIndex in AuthnRequest");
            }
            return Collections.emptyMap();
        }

        Map<String, String> claimsMap = new HashMap<String, String>();
        Set<Claim> aggregatedClaims = authenticationContext.getSequenceContext().getAllClaims();
        String profileName = authenticationContext.getServiceProvider().getClaimConfig().getProfile();
        String dialect = authenticationContext.getServiceProvider().getClaimConfig().getDialectUri();

        if (StringUtils.isEmpty(dialect)) {
            dialect = "default";
        }

        aggregatedClaims = SAML2InboundAuthDataHolder.getInstance()
                .getGatewayClaimResolverService().transformToOtherDialect(aggregatedClaims, dialect, Optional
                        .ofNullable(profileName));

        aggregatedClaims.stream().forEach(claim -> claimsMap.put(claim.getClaimUri(), claim.getValue()));
        return claimsMap;
    }

    // Move to SequenceContext/AuthenticationContext in Gateway
    public static String getSubject(AuthenticationContext authenticationContext, String inResponseTo,
                                    String acsUrl)
            throws SAML2SSOResponseBuilderException {

        SequenceContext sequenceContext = authenticationContext.getSequenceContext();
        int lastStep = sequenceContext.getCurrentStep();
        boolean isUserIdStepFound = false;
        for (int i = 1; i < lastStep - 1; i++) {
            boolean isSubjectStep = false;
            AuthenticationStepConfig stepConfig = authenticationContext.getSequence().getAuthenticationStepConfig(i);
            // update isSubjectStep using stepConfig
            if (isSubjectStep && isUserIdStepFound) {
                SAML2SSOResponseBuilderException ex =
                        new SAML2SSOResponseBuilderException(StatusCode.RESPONDER_URI,
                                                             "Invalid subject step configuration. Multiple subject steps found.");
                ex.setInResponseTo(inResponseTo);
                ex.setAcsUrl(acsUrl);
                throw ex;
            } else {
                isUserIdStepFound = true;
                SequenceContext.StepContext stepContext = sequenceContext.getStepContext(i);
                return stepContext.getUser().getUserIdentifier();
            }
        }
        return null;
    }

    /**
     * TODO: ideally this method must be in identity.commons. However the one in identity.commons uses
     * TODO: java.util.Base64 which doesn't work here. Only the OpenSAML Base64 decoder works. Until then duplicating
     * TODO: this method.
     * Decode X509 certificate.
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws java.security.cert.CertificateException Error when decoding certificate
     */
    public static Certificate decodeCertificate(String encodedCert) throws CertificateException {

        if (encodedCert != null) {
            byte[] bytes = Base64.decode(encodedCert);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory
                    .generateCertificate(new ByteArrayInputStream(bytes));
            return cert;
        } else {
            String errorMsg = "Invalid encoded certificate: \'NULL\'";
            logger.debug(errorMsg);
            throw new IllegalArgumentException(errorMsg);
        }
    }
}
