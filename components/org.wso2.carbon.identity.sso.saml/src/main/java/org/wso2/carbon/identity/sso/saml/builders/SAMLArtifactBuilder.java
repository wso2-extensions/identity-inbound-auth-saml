/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.dao.SAMLArtifactDAO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SAMLArtifactBuilder {

    private static Log log = LogFactory.getLog(SAMLArtifactBuilder.class);

    /**
     * Build the SAML V2.0 Artifact type of Type Code 0x0004 and save it with SAML assertion, in the database.
     * Artifact length : 44 bytes
     * <p>
     * SAML V2.0 defines an artifact type of type code 0x0004
     * Identification:urn:oasis:names:tc:SAML:2.0:artifact-04
     * <p>
     * SAML_artifact := B64(TypeCode EndpointIndex RemainingArtifact)
     * TypeCode := Byte1Byte2
     * EndpointIndex := Byte1Byte2
     * <p>
     * TypeCode := 0x0004
     * RemainingArtifact := SourceID MessageHandle
     * SourceID := 20-byte_sequence
     * MessageHandle := 20-byte_sequence
     *
     * @param authnReqDTO    SAML SSO authentication request.
     * @param sessionIndexId Session index ID.
     * @return SAML V2.0 Artifact type of Type Code 0x0004
     */
    public String buildAndSaveSAML2Artifact(SAMLSSOAuthnReqDTO authnReqDTO, String sessionIndexId)
            throws IdentityException, NoSuchAlgorithmException {

        log.debug("Building SAML2 Artifact");
        if (log.isDebugEnabled()) {
            log.debug("Building SAML2 Artifact");
        }

        // Creating SAML assertion
        DateTime issueInstant = new DateTime();
        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                + SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 * 1000L);

        Assertion samlAssertion = SAMLSSOUtil.buildSAMLAssertion(authnReqDTO, notOnOrAfter, sessionIndexId);

        //Endpoint Index
        byte[] endpointIndex = {0, 0};

        //Source ID
        MessageDigest sha1Digester = MessageDigest.getInstance("SHA-1");
        String issuerID = SAMLSSOUtil.getIssuer().getValue();
        byte[] sourceID = sha1Digester.digest(issuerID.getBytes());

        //MessageHandle
        SecureRandom secureRandom = new SecureRandom();
        byte[] messageHandler = new byte[20];
        secureRandom.nextBytes(messageHandler);

        byte[] artifactByteArray = new byte[44];
        System.arraycopy(SAMLSSOConstants.SAML2_ARTIFACT_TYPE_CODE, 0, artifactByteArray, 0, 2);
        System.arraycopy(endpointIndex, 0, artifactByteArray, 2, 2);
        System.arraycopy(sourceID, 0, artifactByteArray, 4, 20);
        System.arraycopy(messageHandler, 0, artifactByteArray, 24, 20);

        // Storing artifact details
        SAMLArtifactDAO samlArtifactDAO = new SAMLArtifactDAO();
        samlArtifactDAO.storeArtifact(SAMLSSOConstants.SAML2_ARTIFACT_TYPE_CODE, endpointIndex, sourceID,
                messageHandler, samlAssertion, "INITIATED");

        return Base64.encode(artifactByteArray);
    }
}
