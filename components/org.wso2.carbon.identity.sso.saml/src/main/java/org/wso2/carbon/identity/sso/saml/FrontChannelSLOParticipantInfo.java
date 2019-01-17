/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.sso.saml.cache.CacheEntry;

/**
 * Information of front-channel enabled session participants in a single logout.
 */
public class FrontChannelSLOParticipantInfo extends CacheEntry {

    private String originalIssuerLogoutRequestId;
    private String originalIssuer;
    private String logoutRequestIssuingSP;
    private String sessionIndex;

    public FrontChannelSLOParticipantInfo() {

    }

    public FrontChannelSLOParticipantInfo(String originalIssuerLogoutRequestId, String originalIssuer,
                                          String logoutRequestIssuingSP, String sessionIndex) {

        this.originalIssuerLogoutRequestId = originalIssuerLogoutRequestId;
        this.originalIssuer = originalIssuer;
        this.logoutRequestIssuingSP = logoutRequestIssuingSP;
        this.sessionIndex = sessionIndex;
    }

    public String getOriginalIssuerLogoutRequestId() {

        return originalIssuerLogoutRequestId;
    }

    public void setOriginalIssuerLogoutRequestId(String originalIssuerLogoutRequestId) {

        this.originalIssuerLogoutRequestId = originalIssuerLogoutRequestId;
    }

    public String getLogoutRequestIssuingSP() {

        return logoutRequestIssuingSP;
    }

    public void setLogoutRequestIssuingSP(String logoutRequestIssuingSP) {

        this.logoutRequestIssuingSP = logoutRequestIssuingSP;
    }

    public String getSessionIndex() {

        return sessionIndex;
    }

    public void setSessionIndex(String sessionIndex) {

        this.sessionIndex = sessionIndex;
    }

    public String getOriginalIssuer() {

        return originalIssuer;
    }

    public void setOriginalIssuer(String originalIssuer) {

        this.originalIssuer = originalIssuer;
    }
}
