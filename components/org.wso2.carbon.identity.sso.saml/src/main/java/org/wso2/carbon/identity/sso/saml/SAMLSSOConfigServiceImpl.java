/*
 * Copyright (c) (2019-2023), WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
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

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.core.keystore.KeyStoreAdmin;
import org.wso2.carbon.core.keystore.KeyStoreManagementException;
import org.wso2.carbon.core.keystore.service.KeyStoreData;
import org.wso2.carbon.core.util.KeyStoreUtil;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.admin.SAMLSSOConfigAdmin;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.exceptions.RegistryException;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.ClaimMapping;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Collection;
import java.util.function.Predicate;

import static org.wso2.carbon.identity.sso.saml.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.sso.saml.Error.UNEXPECTED_SERVER_ERROR;
import static org.wso2.carbon.identity.sso.saml.Error.URL_NOT_FOUND;

/**
 * Providers an OSGi service layer for SAML service provider configuration management operations.
 */
public class SAMLSSOConfigServiceImpl {

    private static final Log log = LogFactory.getLog(SAMLSSOConfigServiceImpl.class);

    private static final String CONNECTION_TIMEOUT_XPATH = "SSOService.SAMLMetadataUrlConnectionTimeout";
    private static final String READ_TIMEOUT_XPATH = "SSOService.SAMLMetadataUrlReadTimeout";
    private static final String MAX_SIZE_XPATH = "SSOService.SAMLMetadataUrlResponseMaxSize";

    private static final int CONNECTION_TIMEOUT_IN_MILLIS = 5000;
    private static final int READ_TIMEOUT_IN_MILLIS = 5000;
    private static final int MAX_SIZE_IN_BYTES = 51200;

    /**
     * @param spDto
     * @return
     * @throws IdentityException
     */
    public boolean addRPServiceProvider(SAMLSSOServiceProviderDTO spDto) throws IdentityException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            return configAdmin.addRelyingPartyServiceProvider(spDto);
        } catch (IdentityException ex) {
            throw handleException("Error while creating SAML SP in tenantDomain: " + getTenantDomain(), ex);
        }
    }

    /**
     * Updates a SAML service provider.
     *
     * @param serviceProviderDTO    DTO containing the SAML SP configuration.
     * @param currentIssuer         Issuer of the service provider before the update.
     * @return True if the SAML SP is updated successfully.
     * @throws IdentityException If an error occurs while updating the SAML SP.
     */
    public boolean updateRPServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO, String currentIssuer)
            throws IdentityException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            return configAdmin.updateRelyingPartyServiceProvider(serviceProviderDTO, currentIssuer);
        } catch (IdentityException ex) {
            throw handleException("Error while updating SAML SP in tenantDomain: " + getTenantDomain(), ex);
        }
    }

    /**
     * Creates a SAML service provider.
     *
     * @param spDto DTO containing the SAML SP configuration.
     * @return SAMLSSOServiceProviderDTO with the information on the created SAML SP.
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO createServiceProvider(SAMLSSOServiceProviderDTO spDto) throws IdentityException {

        validateSAMLSSOServiceProviderDTO(spDto);
        SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
        try {
            return configAdmin.addSAMLServiceProvider(spDto);
        } catch (IdentityException ex) {
            throw handleException("Error while creating SAML SP in tenantDomain: " + getTenantDomain(), ex);
        }
    }

    /**
     * Update a SAML service provider.
     *
     * @param serviceProviderDTO DTO containing the SAML SP configuration.
     * @param currentIssuer      Issuer of the service provider before the update.
     * @return SAMLSSOServiceProviderDTO with the information on the SAML SP.
     * @throws IdentityException If an error occurs while updating the SAML SP.
     */
    public SAMLSSOServiceProviderDTO updateServiceProvider(SAMLSSOServiceProviderDTO serviceProviderDTO, String currentIssuer)
            throws IdentityException {

        validateSAMLSSOServiceProviderDTO(serviceProviderDTO);
        SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
        try {
            return configAdmin.updateSAMLServiceProvider(serviceProviderDTO, currentIssuer);
        } catch (IdentityException ex) {
            throw handleException("Error while updating SAML SP in tenantDomain: " + getTenantDomain(), ex);
        }
    }

    private void validateSAMLSSOServiceProviderDTO(SAMLSSOServiceProviderDTO serviceProviderDTO) throws IdentityException {

        if (StringUtils.isBlank(serviceProviderDTO.getSigningAlgorithmURI())
                || !Arrays.asList(getSigningAlgorithmUris()).contains(serviceProviderDTO.getSigningAlgorithmURI())) {
            throw buildClientException(INVALID_REQUEST,
                    "Invalid Response Signing Algorithm: " + serviceProviderDTO.getSigningAlgorithmURI());
        }
        if (StringUtils.isBlank(serviceProviderDTO.getDigestAlgorithmURI())
                || !Arrays.asList(getDigestAlgorithmURIs()).contains(serviceProviderDTO.getDigestAlgorithmURI())) {
            throw buildClientException(INVALID_REQUEST,
                    "Invalid Response Digest Algorithm: " + serviceProviderDTO.getDigestAlgorithmURI());
        }
        if (StringUtils.isBlank(serviceProviderDTO.getAssertionEncryptionAlgorithmURI())
                || !Arrays.asList(getAssertionEncryptionAlgorithmURIs()).contains
                (serviceProviderDTO.getAssertionEncryptionAlgorithmURI())) {
            throw buildClientException(INVALID_REQUEST,
                    "Invalid Assertion Encryption Algorithm: " + serviceProviderDTO.getAssertionEncryptionAlgorithmURI());
        }
        if (StringUtils.isBlank(serviceProviderDTO.getKeyEncryptionAlgorithmURI())
                || !Arrays.asList(getKeyEncryptionAlgorithmURIs()).contains(serviceProviderDTO.getKeyEncryptionAlgorithmURI())) {
            throw buildClientException(INVALID_REQUEST,
                    "Invalid Key Encryption Algorithm: " + serviceProviderDTO.getKeyEncryptionAlgorithmURI());
        }
    }

    /**
     * @param metadata
     * @return
     * @throws IdentitySAML2SSOException
     */

    public SAMLSSOServiceProviderDTO uploadRPServiceProvider(String metadata) throws IdentitySAML2SSOException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            if (log.isDebugEnabled()) {
                log.debug("Creating SAML Service Provider with metadata: " + metadata);
            }
            return configAdmin.uploadRelyingPartyServiceProvider(metadata);
        } catch (IdentityException e) {
            String tenantDomain = getTenantDomain();
            throw handleException("Error while uploading SAML SP metadata in tenantDomain: " + tenantDomain, e);
        }
    }

    /**
     * Update a SAML service provider with metadata.
     *
     * @param metadata      Metadata of the SAML SP.
     * @param currentIssuer Issuer of the service provider before the update.
     * @return SAMLSSOServiceProviderDTO with the information on the SAML SP.
     * @throws IdentitySAML2SSOException If an error occurs while updating the SAML SP.
     */
    public SAMLSSOServiceProviderDTO updateRPServiceProviderWithMetadata(String metadata, String currentIssuer)
            throws IdentitySAML2SSOException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            if (log.isDebugEnabled()) {
                log.debug("Updating SAML Service Provider with metadata: " + metadata);
            }
            return configAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, currentIssuer);
        } catch (IdentityException e) {
            throw handleException("Error while updating SAML SP metadata in tenantDomain: " + getTenantDomain(), e);
        }
    }

    /**
     * Create a service provider with configurations provided via a metadata URL.
     *
     * @param metadataUrl URL to fetch the SAML SP metadata file.
     * @return SAMLSSOServiceProviderDTO with the information on the created SAML SP.
     * @throws IdentitySAML2SSOException
     */
    public SAMLSSOServiceProviderDTO createServiceProviderWithMetadataURL(String metadataUrl)
            throws IdentitySAML2SSOException {

        try {
            URL url = new URL(metadataUrl);
            URLConnection con = url.openConnection();
            con.setConnectTimeout(getConnectionTimeoutInMillis());
            con.setReadTimeout(getReadTimeoutInMillis());
            try (InputStream inputStream = new BoundedInputStream(con.getInputStream(), getMaxSizeInBytes())) {
                String metadata = IOUtils.toString(inputStream);
                return uploadRPServiceProvider(metadata);
            }
        } catch (IOException e) {
            throw handleIOException(URL_NOT_FOUND, "Non-existing metadata URL for SAML service provider creation in tenantDomain: "
                    + getTenantDomain(), e);
        }
    }

    /**
     * Update a service provider with configurations provided via a metadata URL.
     *
     * @param metadataUrl   URL to fetch the SAML SP metadata file.
     * @param currentIssuer Issuer of the service provider before the update.
     * @return SAMLSSOServiceProviderDTO with the information on the created SAML SP.
     * @throws IdentitySAML2SSOException
     */
    public SAMLSSOServiceProviderDTO updateServiceProviderWithMetadataURL(String metadataUrl, String currentIssuer)
            throws IdentitySAML2SSOException {

        try {
            URL url = new URL(metadataUrl);
            URLConnection connection = url.openConnection();
            connection.setConnectTimeout(getConnectionTimeoutInMillis());
            connection.setReadTimeout(getReadTimeoutInMillis());
            try (InputStream inputStream = new BoundedInputStream(connection.getInputStream(), getMaxSizeInBytes())) {
                String metadata = IOUtils.toString(inputStream);
                return updateRPServiceProviderWithMetadata(metadata, currentIssuer);
            }
        } catch (IOException e) {
            throw handleIOException(URL_NOT_FOUND,
                    "Non-existing metadata URL for SAML service provider creation in tenantDomain: "
                    + getTenantDomain(), e);
        }
    }

    private int getConnectionTimeoutInMillis() {

        return getHttpConnectionConfigValue(CONNECTION_TIMEOUT_XPATH, CONNECTION_TIMEOUT_IN_MILLIS);
    }

    private int getReadTimeoutInMillis() {

        return getHttpConnectionConfigValue(READ_TIMEOUT_XPATH, READ_TIMEOUT_IN_MILLIS);
    }

    private int getMaxSizeInBytes() {

        return getHttpConnectionConfigValue(MAX_SIZE_XPATH, MAX_SIZE_IN_BYTES);
    }

    /**
     * Read HTTP connection configurations from identity.xml file.
     *
     * @param xPath xpath of the config property.
     * @return Config property value.
     */
    private int getHttpConnectionConfigValue(String xPath, int defaultValue) {

        int configValue = defaultValue;
        String config = IdentityUtil.getProperty(xPath);
        if (StringUtils.isNotBlank(config)) {
            try {
                configValue = Integer.parseInt(config);
            } catch (NumberFormatException e) {
                log.error("Provided HTTP connection config value in " + xPath + " should be an integer type. Value : "
                        + config);
            }
        }
        return configValue;
    }

    private IdentitySAML2SSOException handleIOException(Error error, String message, IOException e) {
        return new IdentitySAML2ClientException(error.getErrorCode(), message, e);
    }

    /**
     * @return
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderInfoDTO getServiceProviders() throws IdentityException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            return configAdmin.getServiceProviders();
        } catch (IdentityException ex) {
            String tenantDomain = getTenantDomain();
            throw handleException("Error while retrieving SAML SPs of tenantDomain: " + tenantDomain, ex);
        }
    }

    /**
     * Returns SAML Service provider information
     *
     * @param issuer unique identifier of SAML the service provider.
     * @return SAMLSSOServiceProviderDTO containing service provider configurations.
     * @throws IdentityException
     */
    public SAMLSSOServiceProviderDTO getServiceProvider(String issuer) throws IdentityException {

        try {
            SAMLSSOConfigAdmin configAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            SAMLSSOServiceProviderInfoDTO serviceProviders = configAdmin.getServiceProviders();

            for (SAMLSSOServiceProviderDTO sp : serviceProviders.getServiceProviders()) {
                if (StringUtils.equals(sp.getIssuer(), issuer)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SAML SP found for issuer: " + issuer + " in tenantDomain: " + getTenantDomain());
                    }
                    return sp;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("SAML SP not found for issuer: " + issuer + " in tenantDomain: " + getTenantDomain());
            }
            return null;
        } catch (IdentityException ex) {
            String msg = "Error retrieving SAML SP for issuer: " + issuer + " of tenantDomain: " + getTenantDomain();
            throw handleException(msg, ex);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    private KeyStoreData[] getKeyStores(int tenantId) throws IdentityException {

        try {
            KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
            return admin.getKeyStores(isSuperTenant(tenantId));
        } catch (KeyStoreManagementException e) {
            throw new IdentityException("Error when loading the key stores from registry", e);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getCertAliasOfPrimaryKeyStore() throws IdentityException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();

        KeyStoreData[] keyStores = getKeyStores(tenantId);
        KeyStoreData primaryKeyStore = null;

        Predicate<String> isPrimaryKeyStore = getIsPrimaryKeyStoreFunction(tenantId);
        for (KeyStoreData keyStore : keyStores) {
            if (isPrimaryKeyStore.test(keyStore.getKeyStoreName())) {
                primaryKeyStore = keyStore;
                break;
            }
        }

        if (primaryKeyStore != null) {
            return getStoreEntries(primaryKeyStore.getKeyStoreName());
        }

        String msg = "Primary Keystore cannot be found for tenantDomain: " + getTenantDomain();
        throw buildServerError(msg);
    }

    private Predicate<String> getIsPrimaryKeyStoreFunction(int tenantId) {

        if (isSuperTenant(tenantId)) {
            return KeyStoreUtil::isPrimaryStore;
        } else {
            return keystoreName -> SAMLSSOUtil.generateKSNameFromDomainName(getTenantDomain()).equals(keystoreName);
        }
    }

    private boolean isSuperTenant(int tenantId) {

        return MultitenantConstants.SUPER_TENANT_ID == tenantId;
    }

    public String[] getSigningAlgorithmUris() {

        Collection<String> uris = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().values();
        return uris.toArray(new String[uris.size()]);
    }

    public String getSigningAlgorithmUriByConfig() {

        return IdentityApplicationManagementUtil.getSigningAlgoURIByConfig();
    }

    public String[] getDigestAlgorithmURIs() {

        Collection<String> digestAlgoUris = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().values();
        return digestAlgoUris.toArray(new String[digestAlgoUris.size()]);
    }

    public String getDigestAlgorithmURIByConfig() {

        return IdentityApplicationManagementUtil.getDigestAlgoURIByConfig();
    }

    public String[] getAssertionEncryptionAlgorithmURIs() {

        Collection<String> assertionEncryptionAlgoUris =
                IdentityApplicationManagementUtil.getXMLAssertionEncryptionAlgorithms().values();
        return assertionEncryptionAlgoUris.toArray(new String[assertionEncryptionAlgoUris.size()]);
    }

    public String getAssertionEncryptionAlgorithmURIByConfig() {

        return IdentityApplicationManagementUtil.getAssertionEncryptionAlgorithmURIByConfig();
    }

    public String[] getKeyEncryptionAlgorithmURIs() {

        Collection<String> keyEncryptionAlgoUris =
                IdentityApplicationManagementUtil.getXMLKeyEncryptionAlgorithms().values();
        return keyEncryptionAlgoUris.toArray(new String[keyEncryptionAlgoUris.size()]);
    }

    public String getKeyEncryptionAlgorithmURIByConfig() {

        return IdentityApplicationManagementUtil.getKeyEncryptionAlgorithmURIByConfig();
    }

    /**
     * @param issuer
     * @return
     * @throws IdentityException
     */
    public boolean removeServiceProvider(String issuer) throws IdentityException {

        try {
            SAMLSSOConfigAdmin ssoConfigAdmin = new SAMLSSOConfigAdmin(getConfigSystemRegistry());
            return ssoConfigAdmin.removeServiceProvider(issuer);
        } catch (IdentityException ex) {
            String msg = "Error removing SAML SP with issuer: " + issuer + " in tenantDomain: " + getTenantDomain();
            throw handleException(msg, ex);
        }
    }

    /**
     * @return
     * @throws IdentityException
     */
    public String[] getClaimURIs() throws IdentityException {

        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(CarbonContext
                .getThreadLocalCarbonContext().getUsername());
        String tenantDomain = MultitenantUtils.getTenantDomain(tenantAwareUsername);
        String[] claimUris = null;
        try {
            UserRealm realm = IdentityTenantUtil.getRealm(tenantDomain, tenantAwareUsername);
            String claimDialect = getClaimDialect();
            ClaimMapping[] claims = realm.getClaimManager().getAllClaimMappings(claimDialect);
            claimUris = new String[claims.length];

            for (int i = 0; i < claims.length; i++) {
                Claim claim = claims[i].getClaim();
                claimUris[i] = claim.getClaimUri();
            }

        } catch (IdentityException e) {
            String msg = "Error while getting realm for user: " + tenantAwareUsername + " of tenantDomain: " + tenantDomain;
            throw handleException(msg, e);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String msg = "Error getting all claim URIs for tenantDomain: " + tenantDomain;
            throw buildServerError(msg, e);
        }
        return claimUris;
    }

    private String getClaimDialect() {

        String claimDialect = IdentityUtil.getProperty(IdentityConstants.ServerConfig.SSO_ATTRIB_CLAIM_DIALECT);
        if (StringUtils.isBlank(claimDialect)) {
            // Set the default wso2 carbon claim dialect.
            claimDialect = SAMLSSOConstants.CLAIM_DIALECT_URL;
        }
        return claimDialect;
    }

    /**
     * @param keyStoreName
     * @return
     * @throws IdentityException
     */
    private String[] getStoreEntries(String keyStoreName) throws IdentityException {

        KeyStoreAdmin admin;
        try {
            admin = new KeyStoreAdmin(CarbonContext.getThreadLocalCarbonContext().getTenantId());
            return admin.getStoreEntries(keyStoreName);
        } catch (KeyStoreManagementException e) {
            String message = "Error reading entries from the key store: " + keyStoreName;
            throw new IdentityException(message, e);
        }
    }

    protected String getTenantDomain() {

        return CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    private Registry getConfigSystemRegistry() throws IdentityException {

        String tenantDomain = getTenantDomain();
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            IdentityTenantUtil.getTenantRegistryLoader().loadTenantRegistry(tenantId);
            if (log.isDebugEnabled()) {
                log.debug("Loading tenant registry for tenant domain: " + tenantDomain);
            }
        } catch (RegistryException e) {
            throw new IdentityException("Error loading tenant registry for tenant domain " + tenantDomain, e);
        }

        return (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getRegistry(RegistryType.SYSTEM_CONFIGURATION);
    }

    private Registry getGovernanceRegistry() {

        return (Registry) CarbonContext.getThreadLocalCarbonContext().getRegistry(RegistryType.USER_GOVERNANCE);
    }

    private IdentitySAML2SSOException handleException(String message, IdentityException ex) {

        setErrorCodeIfNotDefined(ex);
        if (ex instanceof IdentitySAML2SSOException) {
            return (IdentitySAML2SSOException) ex;
        } else {
            return new IdentitySAML2SSOException(ex.getErrorCode(), message, ex);
        }
    }

    private void setErrorCodeIfNotDefined(IdentityException ex) {

        if (ex instanceof IdentitySAML2ClientException) {
            setErrorCode(ex, INVALID_REQUEST);
        } else {
            setErrorCode(ex, UNEXPECTED_SERVER_ERROR);
        }
    }

    private void setErrorCode(IdentityException ex, Error errorMessage) {

        if (StringUtils.isBlank(ex.getErrorCode())) {
            ex.setErrorCode(errorMessage.getErrorCode());
        }
    }

    private IdentityException buildServerError(String message) {

        return new IdentityException(UNEXPECTED_SERVER_ERROR.getErrorCode(), message);
    }

    private IdentityException buildServerError(String message, Exception ex) {

        return new IdentityException(UNEXPECTED_SERVER_ERROR.getErrorCode(), message, ex);
    }

    private IdentitySAML2ClientException buildClientException(Error error, String message) {

        return new IdentitySAML2ClientException(error.getErrorCode(), message);
    }
}


