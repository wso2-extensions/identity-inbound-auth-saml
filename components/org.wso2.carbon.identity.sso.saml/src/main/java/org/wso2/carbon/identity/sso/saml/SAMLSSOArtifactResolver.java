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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.builders.ResponseBuilder;
import org.wso2.carbon.identity.sso.saml.dao.SAML2ArtifactInfoDAO;
import org.wso2.carbon.identity.sso.saml.dao.impl.SAMLArtidactInfoDAOImpl;
import org.wso2.carbon.identity.sso.saml.dto.SAMLArtifactInfo;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.security.NoSuchAlgorithmException;

/**
 * This class is used to resolve a previously issued SAML2 artifact.
 */
public class SAMLSSOArtifactResolver {

    private static Log log = LogFactory.getLog(SAMLSSOArtifactResolver.class);

    /**
     * Build and return an ArtifactResponse object when SAML artifact is given.
     *
     * @param artifact SAML artifact given by the requester.
     * @return Built ArtifactResponse object.
     */
    public Response resolveArtifact(String artifact) {

        Response response = null;

        try {
            // Decode and depart SAML artifact.
            byte[] artifactArray = Base64.decode(artifact);
            byte[] sourceID = new byte[20];
            byte[] messageHandler = new byte[20];

            System.arraycopy(artifactArray, 4, sourceID, 0, 20);
            System.arraycopy(artifactArray, 24, messageHandler, 0, 20);

            // Get SAML artifact data from the database.
            SAMLArtifactInfo samlArtifactInfo = new SAMLArtifactInfo();
            samlArtifactInfo.setSourceId(sourceID);
            samlArtifactInfo.setMessageHandler(messageHandler);

            SAML2ArtifactInfoDAO saml2ArtifactInfoDAO = new SAMLArtidactInfoDAOImpl();
            samlArtifactInfo = saml2ArtifactInfoDAO.getSAMLArtifactInfo(sourceID, messageHandler);

            // Build Response.
            if (samlArtifactInfo != null) {
                ResponseBuilder respBuilder = SAMLSSOUtil.getResponseBuilder();
                response = respBuilder.buildResponse(samlArtifactInfo.getAuthnReqDTO(),
                        samlArtifactInfo.getSessionID(), samlArtifactInfo.getInitTimestamp(),
                        samlArtifactInfo.getExpTimestamp());
            }

        } catch (IdentityException | NoSuchAlgorithmException | Base64DecodingException | ArtifactBindingException e) {
            log.warn("Invalid SAML artifact : " + artifact);
        }

        return response;
    }
}
