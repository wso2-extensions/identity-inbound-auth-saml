package org.wso2.carbon.identity.sso.saml;

import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.registry.core.Registry;

public class SAMLSSOServiceProviderServiceImpl implements SAMLSSOServiceProviderService{


    @Override
    public boolean addServiceProvider(Registry registry, SAMLSSOServiceProviderDO serviceProviderDO) throws IdentityException {
        return false;
    }

    @Override
    public SAMLSSOServiceProviderDO uploadServiceProvider(Registry registry, SAMLSSOServiceProviderDO samlssoServiceProviderDO) throws IdentityException {
        return null;
    }

    @Override
    public SAMLSSOServiceProviderDO[] getServiceProviders(Registry registry) throws IdentityException {
        return new SAMLSSOServiceProviderDO[0];
    }

    @Override
    public boolean removeServiceProvider(Registry registry, String issuer) throws IdentityException {
        return false;
    }

    @Override
    public SAMLSSOServiceProviderDO getServiceProvider(Registry registry, String issuer) throws IdentityException {
        return null;
    }

    @Override
    public boolean isServiceProviderExists(Registry registry, String issuer) throws IdentityException {
        return false;
    }
}
