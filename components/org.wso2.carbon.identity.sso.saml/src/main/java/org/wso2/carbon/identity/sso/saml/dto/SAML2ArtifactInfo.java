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

package org.wso2.carbon.identity.sso.saml.dto;

import org.joda.time.DateTime;

/**
 * This class is used to transfer artifact resolve data.
 */
public class SAML2ArtifactInfo {

    private int id;
    private byte[] sourceId;
    private byte[] messageHandler;
    private SAMLSSOAuthnReqDTO authnReqDTO;
    private String sessionID;
    private DateTime initTimestamp;
    private DateTime expTimestamp;
    private String assertionID;

    public SAML2ArtifactInfo() {
    }

    public SAML2ArtifactInfo(int id, SAMLSSOAuthnReqDTO authnReqDTO, String sessionID, DateTime initTimestamp,
                             DateTime expTimestamp) {

        this.id = id;
        this.authnReqDTO = authnReqDTO;
        this.sessionID = sessionID;
        this.initTimestamp = initTimestamp;
        this.expTimestamp = expTimestamp;
    }

    public void setId(int id) {

        this.id = id;
    }

    public void setSourceId(byte[] sourceId) {

        this.sourceId = sourceId;
    }

    public void setMessageHandler(byte[] messageHandler) {

        this.messageHandler = messageHandler;
    }

    public void setAuthnReqDTO(SAMLSSOAuthnReqDTO authnReqDTO) {

        this.authnReqDTO = authnReqDTO;
    }

    public void setSessionID(String sessionID) {

        this.sessionID = sessionID;
    }

    public void setInitTimestamp(DateTime initTimestamp) {

        this.initTimestamp = initTimestamp;
    }

    public void setExpTimestamp(DateTime expTimestamp) {

        this.expTimestamp = expTimestamp;
    }

    public void setAssertionID(String assertionID) {

        this.assertionID = assertionID;
    }

    public int getId() {

        return id;
    }

    public byte[] getSourceId() {

        return sourceId;
    }

    public byte[] getMessageHandler() {

        return messageHandler;
    }

    public SAMLSSOAuthnReqDTO getAuthnReqDTO() {

        return authnReqDTO;
    }

    public String getSessionID() {

        return sessionID;
    }

    public DateTime getInitTimestamp() {

        return initTimestamp;
    }

    public DateTime getExpTimestamp() {

        return expTimestamp;
    }

    public String getAssertionID() {

        return assertionID;
    }
}
