package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;

public interface SAMLSSOServiceProviderService {
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO, String tenantDomain, String userName)
            throws IdentityException;

    /**
     * Get all the relying party service providers
     *
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO[] getServiceProviders(String tenantDomain, String userName)
            throws IdentityException;

    public boolean removeServiceProvider(String issuer, String tenantDomain, String userName) throws IdentityException;

    public SAMLSSOServiceProviderDO getServiceProvider(String issuer, String tenantDomain, String userName)
            throws IdentityException;

    public boolean isServiceProviderExists(String issuer, String tenantDomain, String userName) throws IdentityException;
}
