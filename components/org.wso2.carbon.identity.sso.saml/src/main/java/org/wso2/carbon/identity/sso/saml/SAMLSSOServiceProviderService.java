package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;

/**
 * This interface is used for managing SAML SSO providers. Adding, retrieving and removing service
 * providers are supported here.
 */
public interface SAMLSSOServiceProviderService {

    /**
     * Add a saml service provider.
     * @param serviceProviderDO Service provider information object.
     * @return SAMLSSOServiceProviderDO[]
     * @throws IdentityException
     */
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException;

    /**
     * Get all the saml service providers.
     * @return SAMLSSOServiceProviderDO[]
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO[] getServiceProviders()
            throws IdentityException;

    /**
     * Remove SAML issuer properties from service provider by saml issuer name.
     * @param issuer SAML issuer name.
     * @return True if remove success
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException;

    /**
     * Get SAML issuer properties from service provider by saml issuer name.
     * @param issuer SAML issuer name.
     * @return SAMLSSOServiceProviderDO
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer)
            throws IdentityException;

    /**
     * Check whether SAML issuer exists by saml issuer name.
     * @param issuer SAML issuer name.
     * @return True if exists
     * @throws IdentityException
     */
    public boolean isServiceProviderExists(String issuer) throws IdentityException;
}
