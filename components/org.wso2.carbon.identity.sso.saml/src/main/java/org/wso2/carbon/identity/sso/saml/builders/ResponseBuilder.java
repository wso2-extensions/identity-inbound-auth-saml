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

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;

import java.security.NoSuchAlgorithmException;

public interface ResponseBuilder {

    /**
     * Build response using SAMLSSOAuthnReqDTO and session index.
     *
     * @param authnReqDTO    SAML sso authentication request DTO.
     * @param sessionIndexId Session index ID.
     * @return Built response object.
     * @throws IdentityException
     * @deprecated Use {@link #buildResponse(SAMLSSOAuthnReqDTO, String, DateTime, String)} instead.
     */
    @Deprecated
    Response buildResponse(SAMLSSOAuthnReqDTO authnReqDTO, String sessionIndexId) throws IdentityException;

    /**
     * Build response using SAMLSSOAuthnReqDTO, session index, initiated time and assertion ID.
     *
     * @param authnReqDTO    SAML sso authentication request DTO.
     * @param sessionIndexId Session index ID.
     * @param initTime       Initiated timestamp of the response.
     * @param assetionId     SAML Assertion ID of the response.
     * @return Built response object.
     * @throws IdentityException
     */
    default Response buildResponse(SAMLSSOAuthnReqDTO authnReqDTO, String sessionIndexId, DateTime initTime,
                                   String assetionId) throws IdentityException {

        return buildResponse(authnReqDTO, sessionIndexId);
    }

}
