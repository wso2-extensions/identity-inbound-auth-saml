/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied. See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.query.saml.internal.SAMLQueryServiceComponent;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Implementation class to find user attributes from user store
 *
 * @see SAMLAttributeFinder
 */
public class UserStoreAttributeFinder implements SAMLAttributeFinder {

    private static final Log log = LogFactory.getLog(UserStoreAttributeFinder.class);

    /**
     * This method is used to initialize
     */
    public void init() {

    }

    /**
     * This method is used to establish realmservice and retrieve user information from user store
     *
     * @param user       Name of the user
     * @param attributes Array of requested user attributes
     * @return Map Collection of attribute name and value pairs
     */
    public Map<String, String> getAttributes(String user, String[] attributes) {
        try {
            UserStoreManager userStoreManager = SAMLQueryServiceComponent.getRealmservice().
                    getTenantUserRealm(CarbonContext.getThreadLocalCarbonContext().getTenantId()).
                    getUserStoreManager();

            if (attributes == null || attributes.length == 0) {

                List<String> list = new ArrayList<String>();
                ClaimMapping[] claimMappings = SAMLQueryServiceComponent.getRealmservice()
                        .getTenantUserRealm(CarbonContext.getThreadLocalCarbonContext().getTenantId())
                        .getClaimManager().getAllClaimMappings(UserCoreConstants.DEFAULT_CARBON_DIALECT);
                for (ClaimMapping claimMapping : claimMappings) {
                    if (claimMapping.getClaim() != null && claimMapping.getClaim().getClaimUri() != null) {
                        list.add(claimMapping.getClaim().getClaimUri());
                    }
                }
                attributes = list.toArray(new String[list.size()]);
            }

            return userStoreManager.getUserClaimValues(user, attributes, null);
        } catch (UserStoreException e) {
            log.error(e);
        }

        return null;
    }
}
