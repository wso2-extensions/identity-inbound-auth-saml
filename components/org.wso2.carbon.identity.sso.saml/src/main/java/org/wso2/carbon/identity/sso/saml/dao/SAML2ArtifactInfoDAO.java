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

package org.wso2.carbon.identity.sso.saml.dao;

import org.wso2.carbon.identity.sso.saml.dto.SAMLArtifactInfo;
import org.wso2.carbon.identity.sso.saml.exception.ArtifactBindingException;

/**
 * DAO class to perform CRUD operations on SAMLArtifactInfo.
 */
public interface SAML2ArtifactInfoDAO {

    /**
     * Store SAML artifact in the database.
     *
     * @param samlArtifactInfo SAMLArtifactInfo object with all data.
     */
    void storeArtifactInfo(SAMLArtifactInfo samlArtifactInfo) throws ArtifactBindingException;

    /**
     * Return the SAML2 artifact data of a given SAML2 artifact. Return null otherwise.
     *
     * @param sourceId Extracted source ID of the SAML2 artifact.
     * @param messageHandler Extracted message handler of the SAML2 artifact.
     * @return SAMLArtifactInfo object with data in the database.
     */
    SAMLArtifactInfo getSAMLArtifactInfo(byte[] sourceId, byte[] messageHandler)
            throws ArtifactBindingException;
}
