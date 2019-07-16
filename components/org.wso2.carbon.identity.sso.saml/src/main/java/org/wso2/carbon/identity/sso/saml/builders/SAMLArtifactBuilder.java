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
import org.wso2.carbon.identity.sso.saml.builders.assertion.ExtendedDefaultAssertionBuilder;
import org.wso2.carbon.identity.sso.saml.dao.SAML2ArtifactInfoDAO;
import org.wso2.carbon.identity.sso.saml.dao.impl.SAML2ArtifactInfoDAOImpl;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ArtifactInfo;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * This class is used to build the saml2 artifact.
 */
public class SAMLArtifactBuilder {

    private static final Log log = LogFactory.getLog(SAMLArtifactBuilder.class);

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
     * RemainingArtifact := SourceId MessageHandle
     * SourceId := 20-byte_sequence
     * MessageHandle := 20-byte_sequence
     *
     * @param authnReqDTO    SAML SSO authentication request.
     * @param sessionIndexId Session index ID.
     * @return SAML V2.0 Artifact, type of TypeCode 0x0004
     */
    public String buildSAML2Artifact(SAMLSSOAuthnReqDTO authnReqDTO, String sessionIndexId)
            throws IdentityException, ArtifactBindingException {

        if (log.isDebugEnabled()) {
            log.debug("Building SAML2 Artifact for SP: " + authnReqDTO.getIssuer() +
                    ", subject: " + authnReqDTO.getSubject()  + ", tenant: " + authnReqDTO.getTenantDomain());
        }

        DateTime initTimestamp = new DateTime();
        DateTime expTimestamp = new DateTime(initTimestamp.getMillis()
                + SAMLSSOUtil.getSAML2ArtifactValidityPeriod() * 60 * 1000L);

        byte[] endpointIndex = {0, 0};

        MessageDigest sha1Digester = null;
        try {
            sha1Digester = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new ArtifactBindingException("Couldn't get Message digest instance with algorithm SHA-1.", e);
        }
        String issuerID = SAMLSSOUtil.getIssuer().getValue();
        byte[] sourceId = sha1Digester.digest(issuerID.getBytes());
        String sourceIdString = String.format("%040x", new BigInteger(1, sourceId));

        SecureRandom secureRandom = new SecureRandom();
        byte[] messageHandler = new byte[20];
        secureRandom.nextBytes(messageHandler);
        String messageHandlerString = String.format("%040x", new BigInteger(1, messageHandler));

        byte[] artifactByteArray = new byte[44];
        System.arraycopy(SAMLSSOConstants.SAML2_ARTIFACT_TYPE_CODE, 0, artifactByteArray, 0, 2);
        System.arraycopy(endpointIndex, 0, artifactByteArray, 2, 2);
        System.arraycopy(sourceId, 0, artifactByteArray, 4, 20);
        System.arraycopy(messageHandler, 0, artifactByteArray, 24, 20);

        // Saving assertion to enable querying assertions.
        String assertionId = null;
        if (authnReqDTO.isAssertionQueryRequestProfileEnabled()) {
            Assertion assertion = persistAssertion(authnReqDTO, initTimestamp, sessionIndexId);
            assertionId = assertion.getID();
        }
        persistSAML2ArtifactInfo(sourceIdString, messageHandlerString, authnReqDTO, sessionIndexId, initTimestamp,
                expTimestamp, assertionId);

        return Base64.encode(artifactByteArray);
    }

    private void persistSAML2ArtifactInfo(String sourceId, String messageHandler, SAMLSSOAuthnReqDTO authnReqDTO,
                                          String sessionIndexId, DateTime initTimestamp, DateTime expTimestamp,
                                          String assertionID)
            throws ArtifactBindingException {

        if (log.isDebugEnabled()) {
            log.debug("Persisting SAML2 Artifact for SP: " + authnReqDTO.getIssuer() +
                    ", subject: " + authnReqDTO.getSubject()  + ", tenant: " + authnReqDTO.getTenantDomain());
        }

        // Storing artifact details.
        SAML2ArtifactInfo saml2ArtifactInfo = new SAML2ArtifactInfo();
        saml2ArtifactInfo.setSourceId(sourceId);
        saml2ArtifactInfo.setMessageHandler(messageHandler);
        saml2ArtifactInfo.setAuthnReqDTO(authnReqDTO);
        saml2ArtifactInfo.setSessionID(sessionIndexId);
        saml2ArtifactInfo.setInitTimestamp(initTimestamp);
        saml2ArtifactInfo.setExpTimestamp(expTimestamp);
        saml2ArtifactInfo.setAssertionID(assertionID);

        SAML2ArtifactInfoDAO saml2ArtifactInfoDAO = new SAML2ArtifactInfoDAOImpl();
        saml2ArtifactInfoDAO.storeArtifactInfo(saml2ArtifactInfo);
    }

    private Assertion persistAssertion(SAMLSSOAuthnReqDTO authnReqDTO, DateTime issueInstant, String sessionId)
            throws IdentityException {

        DateTime notOnOrAfter = new DateTime(issueInstant.getMillis()
                + SAMLSSOUtil.getSAMLResponseValidityPeriod() * 60 * 1000L);

        ExtendedDefaultAssertionBuilder assertionBuilder = new ExtendedDefaultAssertionBuilder();
        return assertionBuilder.buildAssertion(authnReqDTO, notOnOrAfter, sessionId);
    }
}
