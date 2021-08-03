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

import org.apache.commons.collections.MapUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
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
    private static final Log log = LogFactory.getLog(SSOSessionPersistenceManager.class);
    private static SSOSessionPersistenceManager sessionPersistenceManager;

    public static SSOSessionPersistenceManager getPersistenceManager() {
        if (sessionPersistenceManager == null) {
            sessionPersistenceManager = new SSOSessionPersistenceManager();
        }
        return sessionPersistenceManager;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #addSessionInfoDataToCache(String, SessionInfoData, String))} instead.
     */
    @Deprecated
    public static void addSessionInfoDataToCache(String key, SessionInfoData sessionInfoData) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        addSessionInfoDataToCache(key, sessionInfoData, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Adds Session Information to the cache.
     *
     * @param key                    Key which cache entry is indexed.
     * @param sessionInfoData        Session Information Data.
     * @param loginTenantDomain      Tenant Domain where cache will add.
     */
    public static void addSessionInfoDataToCache(String key, SessionInfoData sessionInfoData,
                                                 String loginTenantDomain) {

        removeSessionInfoDataFromCache(key, loginTenantDomain);
        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
        SAMLSSOParticipantCacheEntry cacheEntry = new SAMLSSOParticipantCacheEntry();
        cacheEntry.setSessionInfoData(sessionInfoData);
        SAMLSSOParticipantCache.getInstance().addToCache(cacheKey, cacheEntry, loginTenantDomain);
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #addSessionIndexToCache(String, String, String))} instead.
     */
    @Deprecated
    public static void addSessionIndexToCache(String key, String sessionIndex) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        addSessionIndexToCache(key, sessionIndex, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Adds Session Index to the cache.
     *
     * @param key                   Key which cache entry is indexed
     * @param sessionIndex          Session Index.
     * @param loginTenantDomain     Tenant Domain where cache will add.
     */
    public static void addSessionIndexToCache(String key, String sessionIndex, String loginTenantDomain) {

        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
        SAMLSSOSessionIndexCacheEntry cacheEntry = new SAMLSSOSessionIndexCacheEntry();
        cacheEntry.setSessionIndex(sessionIndex);
        SAMLSSOSessionIndexCache.getInstance().addToCache(cacheKey, cacheEntry, loginTenantDomain);
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #getSessionInfoDataFromCache(String, String))} instead.
     */
    @Deprecated
    public static SessionInfoData getSessionInfoDataFromCache(String key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionInfoDataFromCache(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Retrieve the session information from the cache.
     *
     * @param key                Cache key
     * @param loginTenantDomain  Login Tenant Domain
     * @return SessionInfoData
     */
    public static SessionInfoData getSessionInfoDataFromCache(String key, String loginTenantDomain) {

        SessionInfoData sessionInfoData = null;
        SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
        SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().
                getValueFromCache(cacheKey, loginTenantDomain);

        if (cacheEntry != null) {
            sessionInfoData = cacheEntry.getSessionInfoData();
        }

        return sessionInfoData;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #getSessionIndexFromCache(String, String))} instead.
     */
    @Deprecated
    public static String getSessionIndexFromCache(String key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionIndexFromCache(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Retrieve the session index from the cache.
     *
     * @param key                Cache Key.
     * @param loginTenantDomain  Login Tenant Domain.
     * @return session index.
     */
    public static String getSessionIndexFromCache(String key, String loginTenantDomain) {

        String sessionIndex = null;
        SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
        SAMLSSOSessionIndexCacheEntry cacheEntry = SAMLSSOSessionIndexCache.getInstance().
                getValueFromCache(cacheKey, loginTenantDomain);

        if (cacheEntry != null) {
            sessionIndex = cacheEntry.getSessionIndex();
        }

        return sessionIndex;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #removeSessionInfoDataFromCache(String, String))} instead.
     */
    @Deprecated
    public static void removeSessionInfoDataFromCache(String key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        removeSessionInfoDataFromCache(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Clears the Session Information from the cache.
     *
     * @param key                   Cache Key.
     * @param loginTenantDomain     Login Tenant Domain.
     */
    public static void removeSessionInfoDataFromCache(String key, String loginTenantDomain) {

        if (key != null) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(key);
            SAMLSSOParticipantCache.getInstance().clearCacheEntry(cacheKey, loginTenantDomain);
        }
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #removeSessionIndexFromCache(String, String))} instead.
     */
    @Deprecated
    public static void removeSessionIndexFromCache(String key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        removeSessionIndexFromCache(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Clears the session index from cache.
     *
     * @param key                   Cache Key.
     * @param loginTenantDomain     Login Tenant Domain.
     */
    public static void removeSessionIndexFromCache(String key, String loginTenantDomain) {

        if (key != null) {
            SAMLSSOSessionIndexCacheKey cacheKey = new SAMLSSOSessionIndexCacheKey(key);
            SAMLSSOSessionIndexCache.getInstance().clearCacheEntry(cacheKey, loginTenantDomain);
        }
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #persistSession(String, String, SAMLSSOServiceProviderDO, String, String, String, String))} instead.
     */
    @Deprecated
    public void persistSession(String sessionIndex, String subject, SAMLSSOServiceProviderDO spDO,
                               String rpSessionId, String issuer, String assertionConsumerURL)
            throws IdentityException {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        persistSession(sessionIndex, subject, spDO, rpSessionId, issuer, assertionConsumerURL,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Persists Session Information.
     *
     * @param sessionIndex          Session Index
     * @param subject               Subject
     * @param spDO                  SAMLSSOServiceProviderDO
     * @param rpSessionId           Rp Session id
     * @param issuer                Name of the issuer
     * @param assertionConsumerURL  Assertion Consumer URL
     * @param loginTenantDomain     Login Tenant Domain
     */
    public void persistSession(String sessionIndex, String subject, SAMLSSOServiceProviderDO spDO,
                               String rpSessionId, String issuer, String assertionConsumerURL, String loginTenantDomain)
            throws IdentityException {

        SessionInfoData sessionInfoData = getSessionInfoDataFromCache(sessionIndex, loginTenantDomain);

        if (sessionInfoData == null) {
            sessionInfoData = new SessionInfoData();
        }

        //give priority to assertion consuming URL if specified in the request
        if (assertionConsumerURL != null) {
            spDO.setAssertionConsumerUrl(assertionConsumerURL);
        }
        sessionInfoData.setSubject(issuer, subject);
        sessionInfoData.addServiceProvider(spDO.getIssuer(), spDO, rpSessionId);
        addSessionInfoDataToCache(sessionIndex, sessionInfoData, loginTenantDomain);

    }

    /**
     * Get the session infodata for a particular session
     *
     * @param sessionIndex
     * @return
     *
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #getSessionInfo(String, String))} instead.
     */
    @Deprecated
    public SessionInfoData getSessionInfo(String sessionIndex) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionInfo(sessionIndex, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Get the session info data for a particular session.
     *
     * @param sessionIndex          Session Index.
     * @param loginTenantDomain     Login Tenant Domain.
     * @return SessionInfoData
     */
    public SessionInfoData getSessionInfo(String sessionIndex, String loginTenantDomain) {

        return getSessionInfoDataFromCache(sessionIndex, loginTenantDomain);
    }

    /**
     * Remove a particular session
     *
     * @param sessionIndex
     */
    @Deprecated
    public void removeSession(String sessionIndex) {
        removeSessionInfoDataFromCache(sessionIndex);
    }

    /**
     * Check whether this is an existing session
     *
     * @return
     *
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #isExistingSession(String, String))} instead.
     */
    @Deprecated
    public boolean isExistingSession(String sessionIndex) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return isExistingSession(sessionIndex, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Check whether this is an existing session.
     *
     * @param sessionIndex          Session Index.
     * @param loginTenantDomain     Login Tenant Domain.
     * @return true if this is an existing session, or else return false
     */
    public boolean isExistingSession(String sessionIndex, String loginTenantDomain) {

        SessionInfoData sessionInfoData = getSessionInfoDataFromCache(sessionIndex, loginTenantDomain);
        if (sessionInfoData != null) {
            return true;
        }
        return false;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #persistSession(String, String, String))} instead.
     */
    @Deprecated
    public void persistSession(String tokenId, String sessionIndex) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        persistSession(tokenId, sessionIndex, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Adds Session Index to the cache.
     *
     * @param tokenId               Token Id.
     * @param sessionIndex          Session Index.
     * @param loginTenantDomain     Login Tenant Domain.
     */
    public void persistSession(String tokenId, String sessionIndex, String loginTenantDomain) {
        if (tokenId == null) {
            log.debug("SSO Token Id is null.");
            return;
        }
        if (sessionIndex == null) {
            log.debug("SessionIndex is null.");
            return;
        }
        addSessionIndexToCache(tokenId, sessionIndex, loginTenantDomain);

    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #isExistingTokenId(String, String))} instead.
     */
    @Deprecated
    public boolean isExistingTokenId(String tokenId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return isExistingTokenId (tokenId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Checks the token id is an existing one.
     *
     * @param tokenId               Token Id.
     * @param loginTenantDomain     Login Tenant Domain.
     * @return true if token id is a existing one.
     */
    public boolean isExistingTokenId(String tokenId, String loginTenantDomain) {

        String sessionIndex = getSessionIndexFromCache(tokenId, loginTenantDomain);

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
     *
     * @deprecated This method was deprecated to move SAMLSSOParticipantCache to the tenant space.
     * Use {@link #removeSession(String, String, String)} )} instead.
     */
    @Deprecated
    public static void removeSession(String sessionId, String issuer) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        removeSession (sessionId, issuer, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Clear the session when logout is called.
     *
     * @param sessionId         created session id to invalidate
     * @param issuer            name of the issuer
     * @param loginTenantDomain login tenant domain
     */
    public static void removeSession(String sessionId, String issuer, String loginTenantDomain) {

        String sessionIndex = null;
        if (sessionId != null) {
            sessionIndex = getSessionIndexFromCache(sessionId, loginTenantDomain);
            if(log.isDebugEnabled()) {
                log.debug("Retrieved session index from session id with session index " + sessionIndex);
            }
        }

        if (sessionIndex != null) {
            SAMLSSOParticipantCacheKey cacheKey = new SAMLSSOParticipantCacheKey(sessionIndex);
            SAMLSSOParticipantCacheEntry cacheEntry = SAMLSSOParticipantCache.getInstance().
                    getValueFromCache(cacheKey, loginTenantDomain);
            if (issuer != null) {
                if (cacheEntry.getSessionInfoData() != null && cacheEntry.getSessionInfoData().getServiceProviderList() != null) {
                    SAMLSSOServiceProviderDO providerDO = cacheEntry.getSessionInfoData().getServiceProviderList().get(issuer);
                    SessionInfoData sessionInfoData = cacheEntry.getSessionInfoData();
                    if (providerDO != null && providerDO.isDoSingleLogout()) {
                        removeBackChannelSLOEnabledSPs(cacheEntry, sessionIndex, loginTenantDomain);
                    } else {
                        if (sessionInfoData != null) {
                            sessionInfoData.removeServiceProvider(issuer);
                            addSessionInfoDataToCache(sessionIndex, sessionInfoData);
                            if (log.isDebugEnabled()) {
                                log.debug("Removed service provider from session info data  with name " + issuer);
                            }
                        }
                    }
                }
            } else {
                // Remove session participants in IdP initiated back-channel SLO.
                removeBackChannelSLOEnabledSPs(cacheEntry, sessionIndex, loginTenantDomain);
            }
            SAMLSSOParticipantCacheEntry newCacheEntry = SAMLSSOParticipantCache.getInstance().
                    getValueFromCache(cacheKey, loginTenantDomain);
            if (newCacheEntry.getSessionInfoData() == null || MapUtils.isEmpty(newCacheEntry.getSessionInfoData().
                    getServiceProviderList())) {
                //Clear the session info cache if there isn't session data or service providers
                if(log.isDebugEnabled()) {
                    log.debug("Clearing the session data from cache with session index " + sessionIndex + " and issuer " + issuer);
                }
                SAMLSSOParticipantCache.getInstance().clearCacheEntry(cacheKey, loginTenantDomain);
                removeSessionIndexFromCache(sessionId, loginTenantDomain);
            }
        }
    }

    /**
     * Remove back channel slo enabled service providers.
     *
     * @param cacheEntry SAML SSO Participant cache entry
     * @Deprecated The logic of handing session info data cache is improved. Hence deprecating this method to
     * use {@link #removeBackChannelSLOEnabledSPs(SAMLSSOParticipantCacheEntry, String, String)} method.
     */
    @Deprecated
    public static void removeBackChannelSLOEnabledSPs(SAMLSSOParticipantCacheEntry cacheEntry) {

        Set<String> sloSupportedIssuers = new HashSet<String>();
        // Filter out service providers which enabled the single logout and back-channel logout.
        addSLOSupportedIssuers(cacheEntry, sloSupportedIssuers);
        // Remove service providers which enabled the single logout and back-channel logout.
        for (String sloSupportedIssuer : sloSupportedIssuers) {
            cacheEntry.getSessionInfoData().removeServiceProvider(sloSupportedIssuer);
            if (log.isDebugEnabled()) {
                log.debug("Removed back-channel SLO supported service provider from session info data with name "
                        + sloSupportedIssuer);
            }
        }
    }

    private static void addSLOSupportedIssuers(SAMLSSOParticipantCacheEntry cacheEntry,
                                               Set<String> sloSupportedIssuers) {

        for (Map.Entry<String, SAMLSSOServiceProviderDO> entry : cacheEntry.getSessionInfoData().
                getServiceProviderList().entrySet()) {
            if (entry.getValue().isDoSingleLogout() && !entry.getValue().isDoFrontChannelLogout()) {
                sloSupportedIssuers.add(entry.getKey());
            }
        }
    }

    public static void removeBackChannelSLOEnabledSPs(SAMLSSOParticipantCacheEntry cacheEntry, String sessionIndex,
                                                      String loginTenantDomain) {

        Set<String> sloSupportedIssuers = new HashSet<String>();
        SessionInfoData sessionInfoData = cacheEntry.getSessionInfoData();
        // Filter out service providers which enabled the single logout and back-channel logout.
        addSLOSupportedIssuers(cacheEntry, sloSupportedIssuers);
        // Remove service providers which enabled the single logout and back-channel logout.
        for (String sloSupportedIssuer : sloSupportedIssuers) {
            sessionInfoData.removeServiceProvider(sloSupportedIssuer);
            if (log.isDebugEnabled()) {
                log.debug("Removed back-channel SLO supported service provider from session info data with name "
                        + sloSupportedIssuer);
            }
        }
        addSessionInfoDataToCache(sessionIndex, sessionInfoData, loginTenantDomain);
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #getSessionIndexFromTokenId(String, String))} instead.
     */
    @Deprecated
    public String getSessionIndexFromTokenId(String tokenId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getSessionIndexFromTokenId(tokenId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Get the session index from cache.
     *
     * @param tokenId           Token Id.
     * @param loginTenantDomain Login tenant Domain.
     * @return  Session Index.
     */
    public String getSessionIndexFromTokenId(String tokenId, String loginTenantDomain) {

        return getSessionIndexFromCache(tokenId, loginTenantDomain);
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #removeTokenId(String, String))} instead.
     */
    @Deprecated
    public void removeTokenId(String sessionId) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        removeTokenId(sessionId, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Clears the session index from cache.
     *
     * @param sessionId             Session Id.
     * @param loginTenantDomain     Login Tenant Domain.
     */
    public void removeTokenId(String sessionId, String loginTenantDomain) {

        removeSessionIndexFromCache(sessionId, loginTenantDomain);
    }
}
