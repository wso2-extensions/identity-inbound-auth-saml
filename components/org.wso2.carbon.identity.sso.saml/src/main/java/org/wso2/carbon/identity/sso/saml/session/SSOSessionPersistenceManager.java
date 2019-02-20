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
package org.wso2.carbon.identity.sso.saml.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOParticipantCacheKey;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCache;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SAMLSSOSessionIndexCacheKey;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * This class is used to persist the sessions established with Service providers
 */
public class SSOSessionPersistenceManager {

    private static final int CACHE_TIME_OUT = 157680000;
    private static Log log = LogFactory.getLog(SSOSessionPersistenceManager.class);
    private static SSOSessionPersistenceManager sessionPersistenceManager;

    public static SSOSessionPersistenceManager getPersistenceManager() {
        if (sessionPersistenceManager == null) {
            sessionPersistenceManager = new SSOSessionPersistenceManager();
        }
        return sessionPersistenceManager;
    }

    public static void addSessionInfoDataToCache(String key, SessionInfoData sessionInfoData) {

        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
        SAMLSSOParticipantCacheEntry cacheEntry = new SAMLSSOParticipantCacheEntry();
        cacheEntry.setSessionInfoData(sessionInfoData);
        SAMLSSOParticipantCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    public static void addSessionIndexToCache(String key, String sessionIndex) {

        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
        SAMLSSOSessionIndexCacheEntry cacheEntry = new SAMLSSOSessionIndexCacheEntry();
        cacheEntry.setSessionIndex(sessionIndex);
        SAMLSSOSessionIndexCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    public static SessionInfoData getSessionInfoDataFromCache(String key) {

        SessionInfoData sessionInfoData = null;
        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
        SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            sessionInfoData = cacheEntry.getSessionInfoData();
        }

        return sessionInfoData;
    }

    public static String getSessionIndexFromCache(String key) {

        String sessionIndex = null;
        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
        SAMLSSOSessionIndexCacheEntry cacheEntry = SAMLSSOSessionIndexCache.getInstance().getValueFromCache(cacheKey);

        if (cacheEntry != null) {
            sessionIndex = cacheEntry.getSessionIndex();
        }

        return sessionIndex;
    }

    public static void removeSessionInfoDataFromCache(String key) {

        if (key != null) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
            SAMLSSOParticipantCache.getInstance().clearCacheEntry(cacheKey);
        }
    }

    public static void removeSessionIndexFromCache(String key) {

        if (key != null) {
            SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
            SAMLSSOSessionIndexCache.getInstance().clearCacheEntry(cacheKey);
        }
    }

    public void persistSession(String sessionIndex, String subject, SAMLSSOServiceProviderDO spDO,
                               String rpSessionId, String issuer, String assertionConsumerURL)
            throws IdentityException {

        SessionInfoData sessionInfoData = getSessionInfoDataFromCache(sessionIndex);

        if (sessionInfoData == null) {
            sessionInfoData = new SessionInfoData();
        }

        //give priority to assertion consuming URL if specified in the request
        if (assertionConsumerURL != null) {
            spDO.setAssertionConsumerUrl(assertionConsumerURL);
        }
        sessionInfoData.setSubject(issuer, subject);
        sessionInfoData.addServiceProvider(spDO.getIssuer(), spDO, rpSessionId);
        addSessionInfoDataToCache(sessionIndex, sessionInfoData);

    }

    /**
     * Get the session infodata for a particular session
     *
     * @param sessionIndex
     * @return
     */
    public SessionInfoData getSessionInfo(String sessionIndex) {
        return getSessionInfoDataFromCache(sessionIndex);
    }

    /**
     * Remove a particular session
     *
     * @param sessionIndex
     */
    public void removeSession(String sessionIndex) {
        removeSessionInfoDataFromCache(sessionIndex);
    }

    /**
     * Check whether this is an existing session
     *
     * @return
     */
    public boolean isExistingSession(String sessionIndex) {
        SessionInfoData sessionInfoData = getSessionInfoDataFromCache(sessionIndex);
        if (sessionInfoData != null) {
            return true;
        }
        return false;
    }

    public void persistSession(String tokenId, String sessionIndex) {
        if (tokenId == null) {
            log.debug("SSO Token Id is null.");
            return;
        }
        if (sessionIndex == null) {
            log.debug("SessionIndex is null.");
            return;
        }
        addSessionIndexToCache(tokenId, sessionIndex);

    }

    public boolean isExistingTokenId(String tokenId) {

        String sessionIndex = getSessionIndexFromCache(tokenId);

        if (sessionIndex != null) {
            return true;
        }
        return false;
    }

    /**
     * Clear the session when logout is called.
     *
     * @param sessionId created session id to invalidate
     * @param issuer name of the issuer
     */
    public static void removeSession(String sessionId, String issuer) {

        String sessionIndex = null;
        if (sessionId != null) {
            sessionIndex = getSessionIndexFromCache(sessionId);
            if(log.isDebugEnabled()) {
                log.debug("Retrieved session index from session id with session index " + sessionIndex);
            }
        }

        if (sessionIndex != null) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(sessionIndex);
            SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().getValueFromCache(cacheKey);
            if (issuer != null) {
                if (cacheEntry.getSessionInfoData() != null && cacheEntry.getSessionInfoData().getServiceProviderList() != null) {
                    SAMLSSOServiceProviderDO providerDO = cacheEntry.getSessionInfoData().getServiceProviderList().get(issuer);
                    if (providerDO != null && providerDO.isDoSingleLogout()) {
                        removeBackChannelSLOEnabledSPs(cacheEntry);
                    } else {
                        if(cacheEntry.getSessionInfoData() != null) {
                            cacheEntry.getSessionInfoData().removeServiceProvider(issuer);
                            if(log.isDebugEnabled()) {
                                log.debug("Removed service provider from session info data  with name " + issuer);
                            }
                        }
                    }
                }
            } else {
                // Remove session participants in IdP initiated back-channel SLO.
                removeBackChannelSLOEnabledSPs(cacheEntry);
            }

            if (cacheEntry.getSessionInfoData() == null || cacheEntry.getSessionInfoData().getServiceProviderList() == null ||
                    cacheEntry.getSessionInfoData().getServiceProviderList().isEmpty()) {
                //Clear the session info cache if there isn't session data or service providers
                if(log.isDebugEnabled()) {
                    log.debug("Clearing the session data from cache with session index " + sessionIndex + " and issuer " + issuer);
                }
                SAMLSSOParticipantCache.getInstance().clearCacheEntry(cacheKey);
                removeSessionIndexFromCache(sessionId);
            }
        }
    }

    public static void removeBackChannelSLOEnabledSPs(SAMLSSOParticipantCacheEntry cacheEntry) {

        Set<String> sloSupportedIssuers = new HashSet<String>();
        // Filter out service providers which enabled the single logout and back-channel logout.
        for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : cacheEntry.getSessionInfoData().
                getServiceProviderList().entrySet()) {
            if (entry.getValue().isDoSingleLogout() && !entry.getValue().isDoFrontChannelLogout()) {
                sloSupportedIssuers.add(entry.getKey());
            }
        }
        // Remove service providers which enabled the single logout and back-channel logout.
        for (String sloSupportedIssuer : sloSupportedIssuers) {
            cacheEntry.getSessionInfoData().removeServiceProvider(sloSupportedIssuer);
            if (log.isDebugEnabled()) {
                log.debug("Removed back-channel SLO supported service provider from session info data with name "
                        + sloSupportedIssuer);
            }
        }
    }

    public String getSessionIndexFromTokenId(String tokenId) {
        return getSessionIndexFromCache(tokenId);
    }

    public void removeTokenId(String sessionId) {
        removeSessionIndexFromCache(sessionId);
    }
}
