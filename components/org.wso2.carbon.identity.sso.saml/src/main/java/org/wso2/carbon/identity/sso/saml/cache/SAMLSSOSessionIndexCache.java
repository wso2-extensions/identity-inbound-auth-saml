/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.cache;

import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.core.cache.BaseCache;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;

public class SAMLSSOSessionIndexCache extends BaseCache<SAMLSSOSessionIndexCacheKey, SAMLSSOSessionIndexCacheEntry> {

    private static final String CACHE_NAME = "SAMLSSOSessionIndexCache";
    private static volatile SAMLSSOSessionIndexCache instance;

    private SAMLSSOSessionIndexCache() {
        super(CACHE_NAME);
    }

    public static SAMLSSOSessionIndexCache getInstance() {
        if (instance == null) {
            synchronized (SAMLSSOSessionIndexCache.class) {
                if (instance == null) {
                    instance = new SAMLSSOSessionIndexCache();
                }
            }
        }
        return instance;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #addToCache(SAMLSSOSessionIndexCacheKey, SAMLSSOSessionIndexCacheEntry, String))} instead.
     */
    @Deprecated
    public void addToCache(SAMLSSOSessionIndexCacheKey key, SAMLSSOSessionIndexCacheEntry entry) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        addToCache(key, entry, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Adds Session Index to the cache and session data store.
     *
     * @param key               Key which cache entry is indexed.
     * @param entry             SAMLSSOSessionIndex Cache Entry.
     * @param loginTenantDomain Login Tenant Domain where cache will add.
     */
    @Override
    public void addToCache(SAMLSSOSessionIndexCacheKey key, SAMLSSOSessionIndexCacheEntry entry,
                           String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        super.addToCache(key, entry, tenantDomain);
        SessionDataStore.getInstance().storeSessionData(key.getTokenId(), CACHE_NAME, entry);
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #getValueFromCache(SAMLSSOSessionIndexCacheKey, String))} instead.
     */
    @Deprecated
    public SAMLSSOSessionIndexCacheEntry getValueFromCache(SAMLSSOSessionIndexCacheKey key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        return getValueFromCache(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Retrieve the session Index from the cache.
     * At a cache miss data is loaded from the Session Data Store.
     *
     * @param key                SAMLSSOSessionIndexCacheKey Key which cache entry is indexed.
     * @param loginTenantDomain  Login Tenant Domain.
     * @return Cache entry
     */
    @Override
    public SAMLSSOSessionIndexCacheEntry getValueFromCache(SAMLSSOSessionIndexCacheKey key, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        SAMLSSOSessionIndexCacheEntry cacheEntry = super.getValueFromCache(key, tenantDomain);
        if (cacheEntry == null) {
            cacheEntry = (SAMLSSOSessionIndexCacheEntry) SessionDataStore.getInstance().getSessionData(key.getTokenId(),
                    CACHE_NAME);
        }
        return cacheEntry;
    }

    /**
     * @deprecated This method was deprecated to move SAMLSSOSessionIndexCache to the tenant space.
     * Use {@link #clearCacheEntry(SAMLSSOSessionIndexCacheKey, String))} instead.
     */
    @Deprecated
    public void clearCacheEntry(SAMLSSOSessionIndexCacheKey key) {

        // For backward compatibility, SUPER_TENANT_DOMAIN was used as the cache maintaining tenant.
        clearCacheEntry(key, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    /**
     * Clears the Session Index from the cache and remove from session data store.
     *
     * @param key                   Key to clear cache.
     * @param loginTenantDomain     Login Tenant Domain where cache was added.
     */
    @Override
    public void clearCacheEntry(SAMLSSOSessionIndexCacheKey key, String loginTenantDomain) {

        String tenantDomain = resolveCacheTenantDomain(loginTenantDomain);
        super.clearCacheEntry(key, tenantDomain);
        SessionDataStore.getInstance().clearSessionData(key.getTokenId(), CACHE_NAME);
    }

    /**
     * Return the tenant domain where the cache needed to be maintain.
     *
     * @param tenantDomain login tenant domain.
     * @return tenantDomain Tenant Domain where the cache needed to be maintain.
     */
    private String resolveCacheTenantDomain(String tenantDomain) {

        // If tenanted sessions are not enabled, maintain caches in the super tenant domain.
        if (!IdentityTenantUtil.isTenantedSessionsEnabled()) {
            return MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        return tenantDomain;
    }
}
