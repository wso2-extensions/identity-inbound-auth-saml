/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.sso.saml.internal;

import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;

/**
 * Identity SAML SSO Service Component Holder.
 */
public class IdentitySAMLSSOServiceComponentHolder {

    private SAMLSSOServiceProviderManager samlSSOServiceProviderManager;

    private static final IdentitySAMLSSOServiceComponentHolder instance = new IdentitySAMLSSOServiceComponentHolder();

    private IdentitySAMLSSOServiceComponentHolder() {

    }

    public static IdentitySAMLSSOServiceComponentHolder getInstance() {

        return instance;
    }

    /**
     * Set SAMLSSOServiceProviderManager.
     *
     * @param samlSSOServiceProviderManager SAMLSSOServiceProviderManager.
     */
    public void setSAMLSSOServiceProviderManager(SAMLSSOServiceProviderManager samlSSOServiceProviderManager) {
        this.samlSSOServiceProviderManager = samlSSOServiceProviderManager;
    }

    /**
     * Get SAMLSSOServiceProviderManager.
     *
     * @return SAMLSSOServiceProviderManager.
     */
    public SAMLSSOServiceProviderManager getSAMLSSOServiceProviderManager() {
        return samlSSOServiceProviderManager;
    }


}
