/*
 * Copyright (c) 2007, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.admin;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml1.core.NameIdentifier;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sp.metadata.saml2.exception.InvalidMetadataException;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;

import java.security.KeyStore;
import java.security.cert.CertificateException;

/**
 * This class is used for managing SAML SSO providers. Adding, retrieving and removing service
 * providers are supported here.
 * In addition to that logic for generating key pairs for tenants except for tenant 0, is included
 * here.
 */
public class SAMLSSOConfigAdmin {

    private static Log log = LogFactory.getLog(SAMLSSOConfigAdmin.class);
    private UserRegistry registry;

    public SAMLSSOConfigAdmin(Registry userRegistry) {
        registry = (UserRegistry) userRegistry;
    }

    /**
     * Add a new service provider
     *
     * @param serviceProviderDTO service Provider DTO
     * @return true if successful, false otherwise
     * @throws IdentityException if fails to load the identity persistence manager
     */
    public boolean addRelyingPartyServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO) throws IdentityException {

        SAMLSSOServiceProviderDO serviceProviderDO = createSAMLSSOServiceProviderDO(serviceProviderDTO);
        IdentityPersistenceManager persistenceManager = IdentityPersistenceManager
                .getPersistanceManager();
        try {
            SAMLSSOServiceProviderDO samlssoServiceProviderDO = SSOServiceProviderConfigManager.getInstance().
                    getServiceProvider(serviceProviderDO.getIssuer());

            if (samlssoServiceProviderDO != null) {
                String message = "A Service Provider with the name " + serviceProviderDO.getIssuer() + " is already loaded" +
                        " from the file system.";
                log.error(message);
                return false;
            }
            return persistenceManager.addServiceProvider(registry, serviceProviderDO);
        } catch (IdentityException e) {
            log.error("Error obtaining a registry for adding a new service provider", e);
            throw IdentityException.error("Error obtaining a registry for adding a new service provider", e);
        }
    }

    /**
     * Save Certificate To Key Store
     *
     * @param serviceProviderDO Service provider data object
     * @throws Exception exception
     */
    private void saveCertificateToKeyStore(SAMLSSOServiceProviderDO serviceProviderDO) throws Exception {

        KeyStoreManager manager = KeyStoreManager.getInstance(registry.getTenantId(), IdentitySAMLSSOServiceComponent
                .getServerConfigurationService(), IdentityTenantUtil.getRegistryService());

        if (MultitenantConstants.SUPER_TENANT_ID == registry.getTenantId()) {

            KeyStore keyStore = manager.getPrimaryKeyStore();

            // Admin should manually add the service provider signing certificate to the keystore file.
            // If the certificate is available we will set the alias of that certificate.
            String alias = keyStore.getCertificateAlias(serviceProviderDO.getX509Certificate());
            if (!StringUtils.isBlank(alias)) {
                serviceProviderDO.setCertAlias(alias);
            } else {
                serviceProviderDO.setCertAlias(null);
            }
        } else {

            String keyStoreName = getKeyStoreName(registry.getTenantId());
            KeyStore keyStore = manager.getKeyStore(keyStoreName);

            // Add new certificate
            keyStore.setCertificateEntry(serviceProviderDO.getIssuer(), serviceProviderDO.getX509Certificate());
            manager.updateKeyStore(keyStoreName, keyStore);
        }
    }

    /**
     * This method returns the key store file name from the domain Name
     *
     * @return key store name
     */
    private String getKeyStoreName(int tenantId) {

        String ksName = IdentityTenantUtil.getTenantDomain(tenantId).replace(".", "-");
        return (ksName + ".jks");
    }

    /**
     * upload SAML SSO service provider metadata directly
     *
     * @param metadata
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO uploadRelyingPartyServiceProvider(String metadata) throws IdentityException {

        IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
        Parser parser = new Parser(registry);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();

        try {
            //pass metadata to samlSSOServiceProvider object
            samlssoServiceProviderDO = parser.parse(metadata, samlssoServiceProviderDO);
        } catch (InvalidMetadataException e) {
            throw IdentityException.error("Error parsing SP metadata", e);
        }

        if (samlssoServiceProviderDO.getX509Certificate() != null) {
            try {
                //save certificate
                this.saveCertificateToKeyStore(samlssoServiceProviderDO);
            } catch (Exception e) {
                throw new IdentityException("Error occurred while setting certificate and alias", e);
            }
        }

        try {
            boolean response = persistenceManager.addServiceProvider(registry, samlssoServiceProviderDO);

            if (response) {
                return createSAMLSSOServiceProviderDTO(samlssoServiceProviderDO);
            } else {
                throw IdentityException.error("Error while adding new service provider");
            }
        } catch (IdentityException e) {
            throw IdentityException.error("Error obtaining a registry for adding a new service provider", e);
        }
    }

    private SAMLSSOServiceProviderDO createSAMLSSOServiceProviderDO(SAMLSSOServiceProviderDTO serviceProviderDTO) throws IdentityException {
        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();

        if (serviceProviderDTO.getIssuer() == null || "".equals(serviceProviderDTO.getIssuer())) {
            String message = "A value for the Issuer is mandatory";
            log.error(message);
            throw IdentityException.error(message);
        }

        if (serviceProviderDTO.getIssuer().contains("@")) {
            String message = "\'@\' is a reserved character. Cannot be used for Service Provider Entity ID";
            log.error(message);
            throw IdentityException.error(message);
        }

        serviceProviderDO.setIssuer(serviceProviderDTO.getIssuer());
        serviceProviderDO.setAssertionConsumerUrls(serviceProviderDTO.getAssertionConsumerUrls());
        serviceProviderDO.setDefaultAssertionConsumerUrl(serviceProviderDTO.getDefaultAssertionConsumerUrl());
        serviceProviderDO.setCertAlias(serviceProviderDTO.getCertAlias());
        serviceProviderDO.setDoSingleLogout(serviceProviderDTO.isDoSingleLogout());
        serviceProviderDO.setSloResponseURL(serviceProviderDTO.getSloResponseURL());
        serviceProviderDO.setSloRequestURL(serviceProviderDTO.getSloRequestURL());
        serviceProviderDO.setLoginPageURL(serviceProviderDTO.getLoginPageURL());
        serviceProviderDO.setDoSignResponse(serviceProviderDTO.isDoSignResponse());
        serviceProviderDO.setDoSignAssertions(serviceProviderDTO.isDoSignAssertions());
        serviceProviderDO.setNameIdClaimUri(serviceProviderDTO.getNameIdClaimUri());
        serviceProviderDO.setSigningAlgorithmUri(serviceProviderDTO.getSigningAlgorithmURI());
        serviceProviderDO.setDigestAlgorithmUri(serviceProviderDTO.getDigestAlgorithmURI());
        serviceProviderDO.setAssertionEncryptionAlgorithmUri(serviceProviderDTO.getAssertionEncryptionAlgorithmURI());
        serviceProviderDO.setKeyEncryptionAlgorithmUri(serviceProviderDTO.getKeyEncryptionAlgorithmURI());
        serviceProviderDO.setAssertionQueryRequestProfileEnabled(serviceProviderDTO
                .isAssertionQueryRequestProfileEnabled());
        serviceProviderDO.setSupportedAssertionQueryRequestTypes(serviceProviderDTO.getSupportedAssertionQueryRequestTypes());
        serviceProviderDO.setEnableSAML2ArtifactBinding(serviceProviderDTO.isEnableSAML2ArtifactBinding());

        if (serviceProviderDTO.getNameIDFormat() == null) {
            serviceProviderDTO.setNameIDFormat(NameIdentifier.EMAIL);
        } else {
            serviceProviderDTO.setNameIDFormat(serviceProviderDTO.getNameIDFormat().replace("/",
                    ":"));
        }

        serviceProviderDO.setNameIDFormat(serviceProviderDTO.getNameIDFormat());

        if (serviceProviderDTO.isEnableAttributeProfile()) {
            String attributeConsumingIndex = serviceProviderDTO.getAttributeConsumingServiceIndex();
            if (StringUtils.isNotEmpty(attributeConsumingIndex)) {
                serviceProviderDO.setAttributeConsumingServiceIndex(attributeConsumingIndex);
            } else {
                serviceProviderDO.setAttributeConsumingServiceIndex(Integer.toString(IdentityUtil.getRandomInteger()));
            }
            serviceProviderDO.setEnableAttributesByDefault(serviceProviderDTO.isEnableAttributesByDefault());
        } else {
            serviceProviderDO.setAttributeConsumingServiceIndex("");
            if (serviceProviderDO.isEnableAttributesByDefault()) {
                log.warn("Enable Attribute Profile must be selected to activate it by default. " +
                        "EnableAttributesByDefault will be disabled.");
            }
            serviceProviderDO.setEnableAttributesByDefault(false);
        }

        if (serviceProviderDTO.getRequestedAudiences() != null && serviceProviderDTO.getRequestedAudiences().length != 0) {
            serviceProviderDO.setRequestedAudiences(serviceProviderDTO.getRequestedAudiences());
        }
        if (serviceProviderDTO.getRequestedRecipients() != null && serviceProviderDTO.getRequestedRecipients().length != 0) {
            serviceProviderDO.setRequestedRecipients(serviceProviderDTO.getRequestedRecipients());
        }
        serviceProviderDO.setIdPInitSSOEnabled(serviceProviderDTO.isIdPInitSSOEnabled());
        serviceProviderDO.setIdPInitSLOEnabled(serviceProviderDTO.isIdPInitSLOEnabled());
        serviceProviderDO.setIdpInitSLOReturnToURLs(serviceProviderDTO.getIdpInitSLOReturnToURLs());
        serviceProviderDO.setDoEnableEncryptedAssertion(serviceProviderDTO.isDoEnableEncryptedAssertion());
        serviceProviderDO.setDoValidateSignatureInRequests(serviceProviderDTO.isDoValidateSignatureInRequests());
        return serviceProviderDO;
    }

    private SAMLSSOServiceProviderDTO createSAMLSSOServiceProviderDTO(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {
        SAMLSSOServiceProviderDTO serviceProviderDTO = new SAMLSSOServiceProviderDTO();

        if (serviceProviderDO.getIssuer() == null || "".equals(serviceProviderDO.getIssuer())) {
            String message = "A value for the Issuer is mandatory";
            log.error(message);
            throw IdentityException.error(message);
        }

        if (serviceProviderDO.getIssuer().contains("@")) {
            String message = "\'@\' is a reserved character. Cannot be used for Service Provider Entity ID";
            log.error(message);
            throw IdentityException.error(message);
        }

        serviceProviderDTO.setIssuer(serviceProviderDO.getIssuer());
        serviceProviderDTO.setAssertionConsumerUrls(serviceProviderDO.getAssertionConsumerUrls());
        serviceProviderDTO.setDefaultAssertionConsumerUrl(serviceProviderDO.getDefaultAssertionConsumerUrl());
        serviceProviderDTO.setCertAlias(serviceProviderDO.getCertAlias());

        try {

            if (serviceProviderDO.getX509Certificate() != null) {
                serviceProviderDTO.setCertificateContent(IdentityUtil.convertCertificateToPEM(
                        serviceProviderDO.getX509Certificate()));
            }
        } catch (CertificateException e) {
            throw new IdentityException("An error occurred while converting the application certificate to " +
                    "PEM content.", e);
        }

        serviceProviderDTO.setDoSingleLogout(serviceProviderDO.isDoSingleLogout());
        serviceProviderDTO.setLoginPageURL(serviceProviderDO.getLoginPageURL());
        serviceProviderDTO.setSloRequestURL(serviceProviderDO.getSloRequestURL());
        serviceProviderDTO.setSloResponseURL(serviceProviderDO.getSloResponseURL());
        serviceProviderDTO.setDoSignResponse(serviceProviderDO.isDoSignResponse());
        serviceProviderDTO.setDoSignAssertions(serviceProviderDO.isDoSignAssertions());
        serviceProviderDTO.setNameIdClaimUri(serviceProviderDO.getNameIdClaimUri());
        serviceProviderDTO.setSigningAlgorithmURI(serviceProviderDO.getSigningAlgorithmUri());
        serviceProviderDTO.setDigestAlgorithmURI(serviceProviderDO.getDigestAlgorithmUri());
        serviceProviderDTO.setAssertionEncryptionAlgorithmURI(serviceProviderDO.getAssertionEncryptionAlgorithmUri());
        serviceProviderDTO.setKeyEncryptionAlgorithmURI(serviceProviderDO.getKeyEncryptionAlgorithmUri());
        serviceProviderDTO.setAssertionQueryRequestProfileEnabled(serviceProviderDO
                .isAssertionQueryRequestProfileEnabled());
        serviceProviderDTO.setSupportedAssertionQueryRequestTypes(serviceProviderDO
                .getSupportedAssertionQueryRequestTypes());
        serviceProviderDTO.setEnableAttributesByDefault(serviceProviderDO.isEnableAttributesByDefault());
        serviceProviderDTO.setEnableSAML2ArtifactBinding(serviceProviderDO.isEnableSAML2ArtifactBinding());

        if (serviceProviderDO.getNameIDFormat() == null) {
            serviceProviderDO.setNameIDFormat(NameIdentifier.EMAIL);
        } else {
            serviceProviderDO.setNameIDFormat(serviceProviderDO.getNameIDFormat().replace("/", ":"));
        }

        serviceProviderDTO.setNameIDFormat(serviceProviderDO.getNameIDFormat());

        if (serviceProviderDO.getAttributeConsumingServiceIndex() != null && !serviceProviderDO
                .getAttributeConsumingServiceIndex().equals("")) {
            serviceProviderDTO.setAttributeConsumingServiceIndex(serviceProviderDO.getAttributeConsumingServiceIndex());
        }

        if (serviceProviderDO.getRequestedAudiences() != null && serviceProviderDO.getRequestedAudiences().length !=
                0) {
            serviceProviderDTO.setRequestedAudiences(serviceProviderDO.getRequestedAudiences());
        }
        if (serviceProviderDO.getRequestedRecipients() != null && serviceProviderDO.getRequestedRecipients().length
                != 0) {
            serviceProviderDTO.setRequestedRecipients(serviceProviderDO.getRequestedRecipients());
        }
        serviceProviderDTO.setIdPInitSSOEnabled(serviceProviderDO.isIdPInitSSOEnabled());
        serviceProviderDTO.setDoEnableEncryptedAssertion(serviceProviderDO.isDoEnableEncryptedAssertion());
        serviceProviderDTO.setDoValidateSignatureInRequests(serviceProviderDO.isDoValidateSignatureInRequests());

        return serviceProviderDTO;
    }

    /**
     * Retrieve all the relying party service providers
     *
     * @return set of RP Service Providers + file path of pub. key of generated key pair
     */
    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {
        SAMLSSOServiceProviderDTO[] serviceProviders = null;
        try {
            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager
                    .getPersistanceManager();
            SAMLSSOServiceProviderDO[] providersSet = persistenceManager.getServiceProviders(registry);
            serviceProviders = new SAMLSSOServiceProviderDTO[providersSet.length];

            for (int i = 0; i < providersSet.length; i++) {
                SAMLSSOServiceProviderDO providerDO = providersSet[i];
                SAMLSSOServiceProviderDTO providerDTO = new SAMLSSOServiceProviderDTO();
                providerDTO.setIssuer(providerDO.getIssuer());
                providerDTO.setAssertionConsumerUrls(providerDO.getAssertionConsumerUrls());
                providerDTO.setDefaultAssertionConsumerUrl(providerDO.getDefaultAssertionConsumerUrl());
                providerDTO.setSigningAlgorithmURI(providerDO.getSigningAlgorithmUri());
                providerDTO.setDigestAlgorithmURI(providerDO.getDigestAlgorithmUri());
                providerDTO.setAssertionEncryptionAlgorithmURI(providerDO.getAssertionEncryptionAlgorithmUri());
                providerDTO.setKeyEncryptionAlgorithmURI(providerDO.getKeyEncryptionAlgorithmUri());
                providerDTO.setCertAlias(providerDO.getCertAlias());
                providerDTO.setAttributeConsumingServiceIndex(providerDO.getAttributeConsumingServiceIndex());
                providerDTO.setDoSignResponse(providerDO.isDoSignResponse());
                providerDTO.setDoSignAssertions(providerDO.isDoSignAssertions());
                providerDTO.setDoSingleLogout(providerDO.isDoSingleLogout());
                providerDTO.setAssertionQueryRequestProfileEnabled(providerDO.isAssertionQueryRequestProfileEnabled());
                providerDTO.setSupportedAssertionQueryRequestTypes(providerDO.getSupportedAssertionQueryRequestTypes());
                providerDTO.setEnableSAML2ArtifactBinding(providerDO.isEnableSAML2ArtifactBinding());

                if (providerDO.getLoginPageURL() == null || "null".equals(providerDO.getLoginPageURL())) {
                    providerDTO.setLoginPageURL("");
                } else {
                    providerDTO.setLoginPageURL(providerDO.getLoginPageURL());
                }

                providerDTO.setSloResponseURL(providerDO.getSloResponseURL());
                providerDTO.setSloRequestURL(providerDO.getSloRequestURL());
                providerDTO.setRequestedClaims(providerDO.getRequestedClaims());
                providerDTO.setRequestedAudiences(providerDO.getRequestedAudiences());
                providerDTO.setRequestedRecipients(providerDO.getRequestedRecipients());
                providerDTO.setEnableAttributesByDefault(providerDO.isEnableAttributesByDefault());
                providerDTO.setNameIdClaimUri(providerDO.getNameIdClaimUri());
                providerDTO.setNameIDFormat(providerDO.getNameIDFormat());

                if (providerDTO.getNameIDFormat() == null) {
                    providerDTO.setNameIDFormat(NameIdentifier.EMAIL);
                }
                providerDTO.setNameIDFormat(providerDTO.getNameIDFormat().replace(":", "/"));

                providerDTO.setIdPInitSSOEnabled(providerDO.isIdPInitSSOEnabled());
                providerDTO.setIdPInitSLOEnabled(providerDO.isIdPInitSLOEnabled());
                providerDTO.setIdpInitSLOReturnToURLs(providerDO.getIdpInitSLOReturnToURLs());
                providerDTO.setDoEnableEncryptedAssertion(providerDO.isDoEnableEncryptedAssertion());
                providerDTO.setDoValidateSignatureInRequests(providerDO.isDoValidateSignatureInRequests());
                serviceProviders[i] = providerDTO;
            }
        } catch (IdentityException e) {
            log.error("Error obtaining a registry intance for reading service provider list", e);
            throw IdentityException.error("Error obtaining a registry intance for reading service provider list", e);
        }

        SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTO = new SAMLSSOServiceProviderInfoDTO();
        serviceProviderInfoDTO.setServiceProviders(serviceProviders);

        //if it is tenant zero
        if (registry.getTenantId() == 0) {
            serviceProviderInfoDTO.setTenantZero(true);
        }
        return serviceProviderInfoDTO;
    }

    /**
     * Remove an existing service provider.
     *
     * @param issuer issuer name
     * @return true is successful
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {
        try {
            IdentityPersistenceManager persistenceManager = IdentityPersistenceManager.getPersistanceManager();
            return persistenceManager.removeServiceProvider(registry, issuer);
        } catch (IdentityException e) {
            log.error("Error removing a Service Provider");
            throw IdentityException.error("Error removing a Service Provider", e);
        }
    }

}
