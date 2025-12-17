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

import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.configuration.mgt.core.ConfigurationManager;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.sso.saml.SAML2InboundAuthConfigHandler;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConfigServiceImpl;
import org.wso2.carbon.identity.organization.management.service.OrganizationManager;
import org.wso2.carbon.identity.organization.resource.hierarchy.traverse.service.OrgResourceResolverService;

/**
 * Identity SAML SSO Service Component Holder.
 */
public class IdentitySAMLSSOServiceComponentHolder {

    private SAMLSSOServiceProviderManager samlSSOServiceProviderManager;
    private SAMLSSOConfigServiceImpl samlSSOConfigService;
    private SAML2InboundAuthConfigHandler saml2InboundAuthConfigHandler;
    private ConfigurationManager configurationManager = null;
    private OrgResourceResolverService orgResourceResolverService;
    private OrganizationManager organizationManager;

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
    
    /**
     * Get SAMLSSOConfigService.
     *
     * @return SAMLSSOConfigService.
     */
    public SAMLSSOConfigServiceImpl getSamlSSOConfigService() {
        
        return samlSSOConfigService;
    }
    
    /**
     * Set SAMLSSOConfigService.
     *
     * @param samlSSOConfigService SAMLSSOConfigService.
     */
    public void setSamlSSOConfigService(SAMLSSOConfigServiceImpl samlSSOConfigService) {
        
        this.samlSSOConfigService = samlSSOConfigService;
    }
    
    /**
     * Get SAML2InboundAuthConfigHandler.
     *
     * @return SAML2InboundAuthConfigHandler.
     */
    public SAML2InboundAuthConfigHandler getSaml2InboundAuthConfigHandler() {
        
        return saml2InboundAuthConfigHandler;
    }
    
    /**
     * Set SAML2InboundAuthConfigHandler.
     *
     * @param saml2InboundAuthConfigHandler SAML2InboundAuthConfigHandler.
     */
    public void setSaml2InboundAuthConfigHandler(SAML2InboundAuthConfigHandler saml2InboundAuthConfigHandler) {
        
        this.saml2InboundAuthConfigHandler = saml2InboundAuthConfigHandler;
    }

    public void setConfigurationManager(ConfigurationManager configurationManager) {

        this.configurationManager = configurationManager;
    }

    public ConfigurationManager getConfigurationManager() {

        return configurationManager;
    }

    public OrgResourceResolverService getOrgResourceResolverService() {

        return orgResourceResolverService;
    }

    public void setOrgResourceResolverService(OrgResourceResolverService orgResourceResolverService) {

        this.orgResourceResolverService = orgResourceResolverService;
    }

    public OrganizationManager getOrganizationManager() {

        return organizationManager;
    }

    public void setOrganizationManager(OrganizationManager organizationManager) {

        this.organizationManager = organizationManager;
    }
}
