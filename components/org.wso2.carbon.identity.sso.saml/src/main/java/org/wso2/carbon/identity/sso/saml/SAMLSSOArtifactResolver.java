package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.dao.SAMLArtifactDAO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.UUID;

public class SAMLSSOArtifactResolver {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolver.class);

    /**
     * Build and return an ArtifactResponse object when SAML artifact is given.
     *
     * @param artifact SAML artifact given by the requester.
     * @return Built ArtifactResponse object.
     */
    public Assertion resolveArtifact(String artifact) {

        Assertion assertion = null;

        try {
            // Decode and depart SAML artifact.
            byte[] artifactArray = Base64.decode(artifact);
            byte[] typeCode = new byte[2];
            byte[] endpointIndex = new byte[2];
            byte[] sourceID = new byte[20];
            byte[] messageHandler = new byte[20];

            System.arraycopy(artifactArray, 0, typeCode, 0, 2);
            System.arraycopy(artifactArray, 2, endpointIndex, 0, 2);
            System.arraycopy(artifactArray, 4, sourceID, 0, 20);
            System.arraycopy(artifactArray, 24, messageHandler, 0, 20);

            // Get SAML assertion from the database.
            SAMLArtifactDAO samlArtifactDAO = new SAMLArtifactDAO();
            assertion = samlArtifactDAO.getSAMLAssertion(typeCode, endpointIndex, sourceID, messageHandler);

        } catch (Exception e) {
            log.warn("Invalid SAML artifact : " + artifact);
        }

        return assertion;
    }
}
