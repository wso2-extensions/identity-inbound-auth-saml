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

import org.wso2.carbon.identity.application.authentication.framework.store.SessionDataStore;
import org.wso2.carbon.identity.application.common.cache.BaseCache;

/**
 * This is to store information of front-channel enabled session participants in a single logout.
 */
public class FrontChannelSLOParticipantStore extends BaseCache<String, FrontChannelSLOParticipantInfo> {

    private static final String CACHE_NAME = "FrontChannelSLOParticipantStore";
    private static volatile FrontChannelSLOParticipantStore instance = new FrontChannelSLOParticipantStore();

    private FrontChannelSLOParticipantStore() {

        super(CACHE_NAME);
    }

    public static FrontChannelSLOParticipantStore getInstance() {

        return instance;
    }

    public void addToCache(String key, FrontChannelSLOParticipantInfo entry) {

        super.addToCache(key, entry);
        SessionDataStore.getInstance().storeSessionData(key, CACHE_NAME, entry);
    }

    public FrontChannelSLOParticipantInfo getValueFromCache(String key) {

        FrontChannelSLOParticipantInfo cacheEntry = super.getValueFromCache(key);
        if (cacheEntry == null) {
            cacheEntry = (FrontChannelSLOParticipantInfo) SessionDataStore.getInstance().
                    getSessionData(key, CACHE_NAME);
        }
        return cacheEntry;
    }

    public void clearCacheEntry(String key) {

        super.clearCacheEntry(key);
        SessionDataStore.getInstance().clearSessionData(key, CACHE_NAME);
    }
}
