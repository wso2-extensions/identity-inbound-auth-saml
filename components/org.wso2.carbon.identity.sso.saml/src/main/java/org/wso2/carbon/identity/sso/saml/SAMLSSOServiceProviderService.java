package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.registry.core.Registry;

public interface SAMLSSOServiceProviderService {
    public boolean addServiceProvider(Registry registry, SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException;

    /**
     * Upload Service Provider
     *
     * @param registry,samlssoServiceProviderDO
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO uploadServiceProvider(Registry registry, SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws IdentityException;

    /**
     * Get all the relying party service providers
     *
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO[] getServiceProviders(Registry registry)
            throws IdentityException;

    public boolean removeServiceProvider(Registry registry, String issuer) throws IdentityException;

    public SAMLSSOServiceProviderDO getServiceProvider(Registry registry, String issuer)
            throws IdentityException;

    public boolean isServiceProviderExists(Registry registry, String issuer) throws IdentityException;
}
