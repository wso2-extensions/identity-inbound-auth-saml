/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.KeyProviderService;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;

import java.security.Key;
import java.security.cert.Certificate;

import static org.wso2.carbon.identity.sso.saml.builders.SignKeyDataHolder.SECURITY_KEY_STORE_KEY_ALIAS;

/**
 * Provide the default implementation to fetch the tenant specific keys.
 * This default implementation is used if there isn't any other implementation
 * registered as an OSGi service.
 */

public class DefaultKeyProvider implements KeyProviderService {

    @Override
    public Key getPrivateKey(String tenantDomain) throws IdentityException {
        Key privateKey;
        int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
        String keyAlias;
        KeyStoreAdmin keyAdmin;
        KeyStoreManager keyMan;

        try {
            if (tenantId != org.wso2.carbon.utils.multitenancy.MultitenantConstants.SUPER_TENANT_ID) {
                String keyStoreName = SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain);
                keyMan = KeyStoreManager.getInstance(tenantId);
                privateKey = keyMan.getPrivateKey(keyStoreName, tenantDomain);
            } else {
                keyAlias = ServerConfiguration.getInstance().getFirstProperty(
                        SECURITY_KEY_STORE_KEY_ALIAS);
                keyAdmin = new KeyStoreAdmin(tenantId, SAMLSSOUtil.getRegistryService().getGovernanceSystemRegistry());
                privateKey = keyAdmin.getPrivateKey(keyAlias, true);
            }
        } catch (Exception e) {
            throw new IdentityException("Error while fetching Private ket for tenant: " + tenantDomain, e);
        }
        return privateKey;
    }

    @Override
    public Certificate getCertificate(String tenantDomain, String alias) throws Exception {
        return null;
    }
}
