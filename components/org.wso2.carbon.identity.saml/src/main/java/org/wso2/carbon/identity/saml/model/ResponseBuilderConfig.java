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

package org.wso2.carbon.identity.saml.model;

import org.opensaml.saml1.core.NameIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

/**
 * SAML2 SSO Response Handler Config Bean.
 */
public class ResponseBuilderConfig implements Serializable {

    private static final long serialVersionUID = 6508235825726363156L;
    private static Logger logger = LoggerFactory.getLogger(ResponseBuilderConfig.class);

    private org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig responseBuilderConfigs;

    public ResponseBuilderConfig(
            org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig responseBuilderConfigs) {
        this.responseBuilderConfigs = responseBuilderConfigs;
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.DEFAULT_ASSERTION_CONSUMER_URL);
    }

    public String getNameIdFormat() {
        String nameIdFormat = NameIdentifier.EMAIL;
        Object nameIDFormatObj = responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.NAME_ID_FORMAT);
        if (nameIDFormatObj != null) {
            nameIdFormat = (String) nameIDFormatObj;
        }
        return nameIdFormat;
    }

    public long getNotOnOrAfterPeriod() {
        try {
            return Long.parseLong((String) responseBuilderConfigs.getProperties().get(
                    SAML2AuthConstants.Config.Name.NOT_ON_OR_AFTER_PERIOD));
        } catch (NumberFormatException e) {
            logger.debug("Error while converting given configuration value to an integer", e);
            return 5L;
        }
    }

    public boolean sendBackClaimsAlways() {
        return Boolean.parseBoolean((String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.SEND_CLAIMS_ALWAYS));
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
    }

    public List<String> getRequestedAudiences() {

        List<String> requestedAudiencesStringList = new ArrayList();
        List requestedAudiencesList = (List) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.REQUESTED_AUDIENCES);
        if (requestedAudiencesList == null || requestedAudiencesList.isEmpty()) {
            return requestedAudiencesStringList;
        }
        requestedAudiencesList.stream().forEach(v -> requestedAudiencesStringList.add((String) v));
        return requestedAudiencesStringList;
    }

    public List<String> getRequestedRecipients() {

        List<String> requestedRecipientStringList = new ArrayList();
        List requestedRecipientList = (List) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.REQUESTED_RECIPIENTS);
        if (requestedRecipientList == null || requestedRecipientList.isEmpty()) {
            return requestedRecipientStringList;
        }
        requestedRecipientList.stream().forEach(v -> requestedRecipientStringList.add((String) v));
        return requestedRecipientStringList;
    }

    public String getDigestAlgorithmUri() {
        String digestAlgorithm = SAML2AuthConstants.XML.DigestAlgorithmURI.SHA1;
        Object digestAlgorithmObj = responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.DIGEST_ALGO);
        if (digestAlgorithmObj != null) {
            digestAlgorithm = (String) digestAlgorithmObj;
        }
        return digestAlgorithm;
    }

    public String getSigningAlgorithmUri() {
        String signatureAlgorithm = SAML2AuthConstants.XML.SignatureAlgorithmURI.RSA_SHA1;
        Object signatureAlgorithmObj = responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.SIGNATURE_ALGO);
        if (signatureAlgorithmObj != null) {
            signatureAlgorithm = (String) signatureAlgorithmObj;
        }
        return signatureAlgorithm;
    }

    public boolean signResponse() {
        return Boolean.valueOf((String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.AUTHN_RESPONSE_SIGNED));
    }

    public boolean encryptAssertion() {
        return Boolean.parseBoolean((String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.AUTHN_RESPONSE_ENCRYPTED));
    }

    public String getEncryptionCertificate() {
        return (String) responseBuilderConfigs.getProperties().get(
                SAML2AuthConstants.Config.Name.ENCRYPTION_CERTIFICATE);
    }
}
