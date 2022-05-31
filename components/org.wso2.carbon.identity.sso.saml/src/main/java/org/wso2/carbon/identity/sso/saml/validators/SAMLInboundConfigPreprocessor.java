package org.wso2.carbon.identity.sso.saml.validators;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.BoundedInputStream;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.application.mgt.ApplicationMgtSystemConfig;
import org.wso2.carbon.identity.application.mgt.dao.ApplicationDAO;
import org.wso2.carbon.identity.application.mgt.validator.ApplicationValidator;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sp.metadata.saml2.exception.InvalidMetadataException;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
import org.wso2.carbon.identity.sso.saml.Error;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponent;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.sso.saml.Error.INVALID_REQUEST;
import static org.wso2.carbon.identity.sso.saml.Error.UNEXPECTED_SERVER_ERROR;
import static org.wso2.carbon.identity.sso.saml.Error.URL_NOT_FOUND;

/**
 * Validator class to be used to validate the SAML inbound properties, before it is persisted.
 */
public class SAMLInboundConfigPreprocessor implements ApplicationValidator {

    private static final String SAMLSSO = "samlsso";
    private static final Log logger = LogFactory.getLog(SAMLInboundConfigPreprocessor.class);

    private static final String ISSUER = "issuer";
    private static final String ISSUER_QUALIFIER = "issuerQualifier";
    private static final String SIGNING_ALGORITHM_URI = "signingAlgorithmURI";
    private static final String DIGEST_ALGORITHM_URI = "digestAlgorithmURI";
    private static final String ASSERTION_ENCRYPTION_ALGORITHM_URI = "assertionEncryptionAlgorithmURI";
    private static final String KEY_ENCRYPTION_ALGORITHM_URI = "keyEncryptionAlgorithmURI";
    private static final String ASSERTION_CONSUMER_URLS = "assertionConsumerUrls";
    private static final String DEFAULT_ASSERTION_CONSUMER_URL = "defaultAssertionConsumerUrl";
    private static final String CERT_ALIAS = "certAlias";
    private static final String DO_SIGN_RESPONSE = "doSignResponse";
    private static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attrConsumServiceIndex";
    private static final String DO_SINGLE_LOGOUT = "doSingleLogout";
    private static final String DO_FRONT_CHANNEL_LOGOUT = "doFrontChannelLogout";
    private static final String FRONT_CHANNEL_LOGOUT_BINDING = "frontChannelLogoutBinding";
    private static final String IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED = "isAssertionQueryRequestProfileEnabled";
    private static final String SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES = "supportedAssertionQueryRequestTypes";
    private static final String ENABLE_SAML2_ARTIFACT_BINDING = "enableSAML2ArtifactBinding";
    private static final String DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE = "doValidateSignatureInArtifactResolve";
    private static final String LOGIN_PAGE_URL = "loginPageURL";
    private static final String SLO_RESPONSE_URL = "sloResponseURL";
    private static final String SLO_REQUEST_URL = "sloRequestURL";
    private static final String REQUESTED_CLAIMS = "requestedClaims";
    private static final String REQUESTED_AUDIENCES = "requestedAudiences";
    private static final String REQUESTED_RECIPIENTS = "requestedRecipients";
    private static final String ENABLE_ATTRIBUTES_BY_DEFAULT = "enableAttributesByDefault";
    private static final String NAME_ID_CLAIM_URI = "nameIdClaimUri";
    private static final String NAME_ID_FORMAT = "nameIDFormat";
    private static final String IDP_INIT_SSO_ENABLED = "idPInitSSOEnabled";
    private static final String IDP_INIT_SLO_ENABLED = "idPInitSLOEnabled";
    private static final String IDP_INIT_SLO_RETURN_TO_URLS = "idpInitSLOReturnToURLs";
    private static final String DO_ENABLE_ENCRYPTED_ASSERTION = "doEnableEncryptedAssertion";
    private static final String DO_VALIDATE_SIGNATURE_IN_REQUESTS = "doValidateSignatureInRequests";
    private static final String IDP_ENTITY_ID_ALIAS = "idpEntityIDAlias";
    private static final String IS_UPDATE = "isUpdate";
    private static final String METADATA_FILE = "metadataFile";
    private static final String METADATA_URL = "metadataUrl";
    private static final String CERTIFICATE = "certificate";

    private static final String INVALID_SIGNING_ALGORITHM_URI = "Invalid Response Signing Algorithm: %s";
    private static final String INVALID_DIGEST_ALGORITHM_URI = "Invalid Response Digest Algorithm: %s";
    private static final String INVALID_ASSERTION_ENCRYPTION_ALGORITHM_URI = "Invalid Assertion Encryption Algorithm:" +
            " %s";
    private static final String INVALID_KEY_ENCRYPTION_ALGORITHM_URI = "Invalid Key Encryption Algorithm: %s";
    private static final String ISSUER_ALREADY_EXISTS = "An application with the SAML issuer: %s already exists in " +
            "tenantDomain: %s";
    private static final String ISSUER_WITH_ISSUER_QUALIFIER_ALREADY_EXISTS = "SAML2 Service Provider already exists " +
            "with the same issuer name: %s and qualifier name: %s , in tenantDomain: %s";

    @Override
    public int getOrderId() {
        return 1;
    }

    @Override
    public List<String> validateApplication(ServiceProvider serviceProvider, String tenantDomain, String username)
            throws IdentityApplicationManagementException {
        List<String> validationErrors = new ArrayList<>();
        InboundAuthenticationRequestConfig requestConfig = getSAMLInboundAuthenticationRequestConfig(serviceProvider);
        if (requestConfig == null || requestConfig.getProperties() == null) {
            return validationErrors;
        }

        //preprocess metadata file or metadata url if exists
        preprocessMetadata(requestConfig);

        //validations
        validateSAMLProperties(validationErrors, requestConfig, tenantDomain);

        //save the certificate if exists
        saveCertificate(validationErrors, requestConfig);

        //remove unnecessary properties
        requestConfig.setProperties(Arrays.stream(requestConfig.getProperties()).filter(property ->
                (!property.getName().equals(IS_UPDATE) && (!property.getName().equals(METADATA_FILE))
                        && (!property.getName().equals(METADATA_URL)) && (!property.getName().equals(CERTIFICATE))))
                .toArray(Property[]::new));

        return validationErrors;
    }

    private void saveCertificate(List<String> validationErrors, InboundAuthenticationRequestConfig requestConfig)
            throws IdentityApplicationManagementException {
        Property[] properties = requestConfig.getProperties();
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));

        if (validationErrors.isEmpty()) {
            try {
                if (map.containsKey(CERTIFICATE) && map.get(CERTIFICATE) != null
                        && StringUtils.isNotBlank(map.get(CERTIFICATE).get(0))) {
                    saveCertificateIfExists(map.get(CERTIFICATE).get(0), requestConfig);
                }
            } catch (IdentityException e) {
                throw new IdentityApplicationManagementException(String.format("Error happened when saving the " +
                        "certificate in tenantDomain: %s", getTenantDomain()), e);
            }
        }
    }

    private void preprocessMetadata(InboundAuthenticationRequestConfig requestConfig)
            throws IdentityApplicationManagementException {
        Property[] properties = requestConfig.getProperties();
        List<Property> propertyList = new ArrayList<>(Arrays.asList(properties));
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));
        try {
            if (map.containsKey(METADATA_FILE)) {
                setPropertiesFromMetadataFile(map.get(METADATA_FILE).get(0), propertyList);
            } else if (map.containsKey(METADATA_URL)) {
                setPropertiesFromMetadataUrl(map.get(METADATA_URL).get(0), propertyList);
            } else {
                return;
            }
            requestConfig.setProperties(propertyList.toArray(new Property[0]));
            map = new HashMap<>(Arrays.stream(requestConfig.getProperties()).collect(Collectors.groupingBy(
                    Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));
            requestConfig.setInboundAuthKey(map.get(ISSUER).get(0));
        } catch (IdentitySAML2SSOException e) {
            throw new IdentityApplicationManagementException("Error happened when preprocessing metadata", e);
        }
    }

    private void validateSAMLProperties(List<String> validationErrors,
                                        InboundAuthenticationRequestConfig inboundAuthenticationRequestConfig,
                                        String tenantDomain) throws IdentityApplicationManagementException {
        Property[] properties = inboundAuthenticationRequestConfig.getProperties();
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));

        validateIssuer(map, validationErrors,  inboundAuthenticationRequestConfig.getInboundAuthKey(), tenantDomain);
        validateIssuerQualifier(map, validationErrors);
        if (map.containsKey(SIGNING_ALGORITHM_URI) && !StringUtils.isBlank(map.get(SIGNING_ALGORITHM_URI).get(0))
                && !Arrays.asList(getSigningAlgorithmUris()).contains(map.get(SIGNING_ALGORITHM_URI).get(0))) {
            validationErrors.add(String.format(INVALID_SIGNING_ALGORITHM_URI, map.get(SIGNING_ALGORITHM_URI).get(0)));
        }

        if (map.containsKey(DIGEST_ALGORITHM_URI) && !StringUtils.isBlank(map.get(DIGEST_ALGORITHM_URI).get(0))
                && !Arrays.asList(getDigestAlgorithmURIs()).contains(map.get(DIGEST_ALGORITHM_URI).get(0))) {
            validationErrors.add(String.format(INVALID_DIGEST_ALGORITHM_URI , map.get(DIGEST_ALGORITHM_URI).get(0)));
        }

        if (map.containsKey(ASSERTION_ENCRYPTION_ALGORITHM_URI)
                && !StringUtils.isBlank(map.get(ASSERTION_ENCRYPTION_ALGORITHM_URI).get(0))
                && !Arrays.asList(getAssertionEncryptionAlgorithmURIs()).contains(
                map.get(ASSERTION_ENCRYPTION_ALGORITHM_URI).get(0))) {
            validationErrors.add(String.format(INVALID_ASSERTION_ENCRYPTION_ALGORITHM_URI,
                    map.get(ASSERTION_ENCRYPTION_ALGORITHM_URI).get(0)));
        }

        if (map.containsKey(KEY_ENCRYPTION_ALGORITHM_URI)
                && !StringUtils.isBlank(map.get(KEY_ENCRYPTION_ALGORITHM_URI).get(0))
                && !Arrays.asList(getKeyEncryptionAlgorithmURIs()).contains(
                map.get(KEY_ENCRYPTION_ALGORITHM_URI).get(0))) {
            validationErrors.add(String.format(INVALID_KEY_ENCRYPTION_ALGORITHM_URI,
                    map.get(KEY_ENCRYPTION_ALGORITHM_URI).get(0)));
        }
    }

    private void setPropertiesFromMetadataUrl(String metadataUrl, List<Property> propertyList)
            throws IdentitySAML2SSOException {
        InputStream in = null;
        try {
            URL url = new URL(metadataUrl);
            URLConnection con = url.openConnection();
            con.setConnectTimeout(getConnectionTimeoutInMillis());
            con.setReadTimeout(getReadTimeoutInMillis());
            in = new BoundedInputStream(con.getInputStream(), getMaxSizeInBytes());

            String metadata = IOUtils.toString(in);
            setPropertiesFromMetadataFile(metadata, propertyList);
        } catch (IOException e) {
            String tenantDomain = getTenantDomain();
            throw handleIOException(URL_NOT_FOUND, "Non-existing metadata URL for SAML service provider creation in " +
                    "tenantDomain: " + tenantDomain, e);
        } finally {
            IOUtils.closeQuietly(in);
        }
    }

    private void setPropertiesFromMetadataFile(String encodedMetaFileContent, List<Property> propertyList)
            throws IdentitySAML2SSOException {
        try {
            byte[] metaData = Base64.getDecoder().decode(encodedMetaFileContent.getBytes(StandardCharsets.UTF_8));
            String base64DecodedMetadata = new String(metaData, StandardCharsets.UTF_8);

            if (logger.isDebugEnabled()) {
                logger.debug("Creating SAML Service Provider with metadata: " + base64DecodedMetadata);
            }
            SAMLSSOServiceProviderDO serviceProviderDO = getServiceProviderDOFromMetadata(base64DecodedMetadata,
                    propertyList);
            if (serviceProviderDO.getNameIDFormat() == null) {
                serviceProviderDO.setNameIDFormat(NameIdentifier.UNSPECIFIED);
            } else {
                serviceProviderDO.setNameIDFormat(serviceProviderDO.getNameIDFormat().replace("/", ":"));
            }
            addSAMLInboundProperties(propertyList, serviceProviderDO);
        } catch (IdentityException e) {
            throw new IdentitySAML2SSOException("Error happend when converting metadata to properties.", e);
        }
    }

    private static void addSAMLInboundProperties(List<Property> propertyList,
                                                 SAMLSSOServiceProviderDO serviceProviderDO) {
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(SAMLSSOUtil.getIssuerWithQualifier(serviceProviderDO.getIssuer(),
                    serviceProviderDO.getIssuerQualifier()));
        }
        addKeyValuePair(ISSUER, serviceProviderDO.getIssuer(), propertyList);
        addKeyValuePair(ISSUER_QUALIFIER, serviceProviderDO.getIssuerQualifier(), propertyList);
        for (String url : serviceProviderDO.getAssertionConsumerUrls()) {
            addKeyValuePair(ASSERTION_CONSUMER_URLS, url, propertyList);
        }
        addKeyValuePair(DEFAULT_ASSERTION_CONSUMER_URL,
                serviceProviderDO.getDefaultAssertionConsumerUrl(), propertyList);
        addKeyValuePair(SIGNING_ALGORITHM_URI, serviceProviderDO.getSigningAlgorithmUri(), propertyList);
        addKeyValuePair(DIGEST_ALGORITHM_URI, serviceProviderDO.getDigestAlgorithmUri(), propertyList);
        addKeyValuePair(ASSERTION_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDO.getAssertionEncryptionAlgorithmUri(), propertyList);
        addKeyValuePair(KEY_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDO.getKeyEncryptionAlgorithmUri(), propertyList);
        addKeyValuePair(CERT_ALIAS, serviceProviderDO.getCertAlias(), propertyList);
        //TODO
        addKeyValuePair(ATTRIBUTE_CONSUMING_SERVICE_INDEX, serviceProviderDO.getAttributeConsumingServiceIndex(),
                propertyList);
        addKeyValuePair(DO_SIGN_RESPONSE, serviceProviderDO.isDoSignResponse() ? "true" : "false", propertyList);
        addKeyValuePair(DO_SINGLE_LOGOUT, serviceProviderDO.isDoSingleLogout() ? "true" : "false", propertyList);
        addKeyValuePair(DO_FRONT_CHANNEL_LOGOUT,
                serviceProviderDO.isDoFrontChannelLogout() ? "true" : "false", propertyList);
        addKeyValuePair(FRONT_CHANNEL_LOGOUT_BINDING,
                serviceProviderDO.getFrontChannelLogoutBinding(), propertyList);
        addKeyValuePair(IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                serviceProviderDO.isAssertionQueryRequestProfileEnabled() ? "true" : "false", propertyList);
        addKeyValuePair(SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                serviceProviderDO.getSupportedAssertionQueryRequestTypes(), propertyList);
        addKeyValuePair(ENABLE_SAML2_ARTIFACT_BINDING,
                serviceProviderDO.isEnableSAML2ArtifactBinding() ? "true" : "false", propertyList);
        addKeyValuePair(DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                serviceProviderDO.isDoValidateSignatureInArtifactResolve() ? "true" : "false", propertyList);
        addKeyValuePair(LOGIN_PAGE_URL, serviceProviderDO.getLoginPageURL(), propertyList);
        addKeyValuePair(SLO_RESPONSE_URL, serviceProviderDO.getSloResponseURL(), propertyList);
        addKeyValuePair(SLO_REQUEST_URL, serviceProviderDO.getSloRequestURL(), propertyList);
        for (String claim : serviceProviderDO.getRequestedClaims()) {
            addKeyValuePair(REQUESTED_CLAIMS, claim, propertyList);
        }
        for (String audience : serviceProviderDO.getRequestedAudiences()) {
            addKeyValuePair(REQUESTED_AUDIENCES, audience, propertyList);
        }
        for (String recipient : serviceProviderDO.getRequestedRecipients()) {
            addKeyValuePair(REQUESTED_RECIPIENTS, recipient, propertyList);
        }
        addKeyValuePair(ENABLE_ATTRIBUTES_BY_DEFAULT,
                serviceProviderDO.isEnableAttributesByDefault() ? "true" : "false", propertyList);
        addKeyValuePair(NAME_ID_CLAIM_URI, serviceProviderDO.getNameIdClaimUri(), propertyList);
        addKeyValuePair(NAME_ID_FORMAT, serviceProviderDO.getNameIDFormat(), propertyList);
        addKeyValuePair(IDP_INIT_SSO_ENABLED,
                serviceProviderDO.isIdPInitSSOEnabled() ? "true" : "false", propertyList);
        addKeyValuePair(IDP_INIT_SLO_ENABLED,
                serviceProviderDO.isIdPInitSLOEnabled() ? "true" : "false", propertyList);
        for (String url : serviceProviderDO.getIdpInitSLOReturnToURLs()) {
            addKeyValuePair(IDP_INIT_SLO_RETURN_TO_URLS, url, propertyList);
        }
        addKeyValuePair(DO_ENABLE_ENCRYPTED_ASSERTION,
                serviceProviderDO.isDoEnableEncryptedAssertion() ? "true" : "false", propertyList);
        addKeyValuePair(DO_VALIDATE_SIGNATURE_IN_REQUESTS,
                serviceProviderDO.isDoValidateSignatureInRequests() ? "true" : "false", propertyList);
        addKeyValuePair(IDP_ENTITY_ID_ALIAS, serviceProviderDO.getIdpEntityIDAlias(), propertyList);
    }

    private static SAMLSSOServiceProviderDO getServiceProviderDOFromMetadata(String metadata,
                                                                             List<Property> propertyList)
            throws IdentityException {
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        Registry registry = getConfigSystemRegistry();
        try {
            Parser parser = new Parser(registry);
            //pass metadata to samlSSOServiceProvider object
            samlssoServiceProviderDO = parser.parse(metadata, samlssoServiceProviderDO);
        } catch (InvalidMetadataException e) {
            throw buildClientException(INVALID_REQUEST, "Error parsing SAML SP metadata.", e);
        }
        if (samlssoServiceProviderDO.getX509Certificate() != null) {
            try {
                String certificate = serializeObjectToString(samlssoServiceProviderDO.getX509Certificate());
                addKeyValuePair(CERTIFICATE, certificate, propertyList);
            } catch (IOException e) {
                throw handleIOException(UNEXPECTED_SERVER_ERROR, "Error while serializing certificate to a string in " +
                        "tenantDomain " + getTenantDomain(), e);
            }
        }
        return samlssoServiceProviderDO;
    }

    private static void addKeyValuePair(String key, String value, List<Property> propertyList) {
        if (value == null) {
            return;
        }
        Property property = new Property();
        property.setName(key);
        property.setValue(value);
        propertyList.add(property);
    }

    private static Registry getConfigSystemRegistry() throws IdentityException {

        String tenantDomain = getTenantDomain();
        try {
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            IdentityTenantUtil.getTenantRegistryLoader().loadTenantRegistry(tenantId);
            if (logger.isDebugEnabled()) {
                logger.debug("Loading tenant registry for tenant domain: " + tenantDomain);
            }
        } catch (RegistryException e) {
            throw new IdentityException("Error loading tenant registry for tenant domain " + tenantDomain, e);
        }

        return (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                .getRegistry(RegistryType.SYSTEM_CONFIGURATION);
    }

    private static IdentitySAML2ClientException buildClientException(Error error, String message, Exception e) {

        return new IdentitySAML2ClientException(error.getErrorCode(), message, e);
    }

    private static String getTenantDomain() {
        return CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }


    private InboundAuthenticationRequestConfig getSAMLInboundAuthenticationRequestConfig(
            ServiceProvider serviceProvider) {
        if (serviceProvider != null && serviceProvider.getInboundAuthenticationConfig() != null &&
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {
            for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authConfig.getInboundAuthType(), SAMLSSO)) {
                    return authConfig;
                }
            }
        }
        return null;
    }

    private void saveCertificateIfExists(String certificate,
                                         InboundAuthenticationRequestConfig requestConfig) throws IdentityException {
        try {

            X509Certificate x509Certificate = deserializeObjectFromString(certificate);
            //save certificate to keystore
            saveCertificateToKeyStore(x509Certificate, requestConfig);
        } catch (IOException e) {
            throw handleIOException(UNEXPECTED_SERVER_ERROR, "Error while deserializing string to certificate in " +
                    "tenantDomain " + getTenantDomain(), e);
        } catch (ClassNotFoundException e) {
            throw new IdentityException("Class not found: X509Certificate", e);
        } catch (Exception e) {
            throw new IdentityException(String.format("Error happened when saving the certificate with the " +
                    "issuer name %s in tenantDomain %s", requestConfig.getInboundAuthKey(), getTenantDomain()), e);
        }

    }

    /**
     * Save Certificate To Key Store
     *
     * @param x509Certificate certificate object
     * @param requestConfig InboundAuthenticationRequestObject with SAML inbound configuration
     * @throws Exception exception
     */
    private static void saveCertificateToKeyStore(X509Certificate x509Certificate,
                                                  InboundAuthenticationRequestConfig requestConfig)
            throws Exception {
        int tenantId = IdentityTenantUtil.getTenantId(getTenantDomain());
        KeyStoreManager manager = KeyStoreManager.getInstance(tenantId, IdentitySAMLSSOServiceComponent
                .getServerConfigurationService(), IdentityTenantUtil.getRegistryService());

        if (MultitenantConstants.SUPER_TENANT_ID == tenantId) {

            KeyStore keyStore = manager.getPrimaryKeyStore();

            // Admin should manually add the service provider signing certificate to the keystore file.
            // If the certificate is available we will set the alias of that certificate.
            String alias = keyStore.getCertificateAlias(x509Certificate);
            if (!StringUtils.isBlank(alias)) {
                Property[] properties = Arrays.stream(requestConfig.getProperties()).filter(property ->
                        (!property.getName().equals(CERT_ALIAS))).toArray(Property[]::new);
                List<Property> propertyList = Arrays.asList(properties);
                addKeyValuePair(CERT_ALIAS, alias, propertyList);
            }
        } else {

            String keyStoreName = getKeyStoreName(tenantId);
            KeyStore keyStore = manager.getKeyStore(keyStoreName);

            // Add new certificate
            keyStore.setCertificateEntry(requestConfig.getInboundAuthKey(), x509Certificate);
            manager.updateKeyStore(keyStoreName, keyStore);
        }
    }
    /**
     * This method returns the key store file name from the domain Name
     *
     * @return key store name
     */
    private static String getKeyStoreName(int tenantId) {

        String ksName = IdentityTenantUtil.getTenantDomain(tenantId).replace(".", "-");
        return (ksName + ".jks");
    }

    private boolean isIssuerExists(String issuer, String tenantDomain) throws IdentityApplicationManagementException {
        ApplicationDAO applicationDAO =  ApplicationMgtSystemConfig.getInstance().getApplicationDAO();
        try {
            if (applicationDAO.getServiceProviderNameByClientId(issuer, SAMLSSO, tenantDomain) != null) {
                return true;
            }
            return false;
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityApplicationManagementException("Error while checking SAML issuer exists", e);
        }
    }

    private void validateIssuerQualifier(HashMap<String, List<String>> map, List<String> validationErrors) {
        if (map.containsKey(ISSUER_QUALIFIER) && (map.get(ISSUER_QUALIFIER) != null)
                && StringUtils.isNotBlank(map.get(ISSUER_QUALIFIER).get(0))
                && map.get(ISSUER_QUALIFIER).get(0).contains("@")) {
            String errorMessage = "\'@\' is a reserved character. Cannot be used for Service Provider Qualifier Value.";
            validationErrors.add(errorMessage);
        }
    }

    private void validateIssuer(HashMap<String, List<String>> map, List<String> validationErrors, String inboundAuthKey,
                                String tenantDomain) throws IdentityApplicationManagementException {

        if (!map.containsKey(ISSUER) || (map.get(ISSUER) == null) || StringUtils.isBlank(map.get(ISSUER).get(0))) {
            validationErrors.add("A value for the Issuer is mandatory.");
            return;
        }

        String issuerWithQualifier = inboundAuthKey;
        String issuerWithoutQualifier = inboundAuthKey;
        if (map.containsKey(ISSUER_QUALIFIER) && (map.get(ISSUER_QUALIFIER) != null)
                && StringUtils.isNotBlank(map.get(ISSUER_QUALIFIER).get(0))) {
            issuerWithoutQualifier = SAMLSSOUtil.getIssuerWithoutQualifier(map.get(ISSUER).get(0));
        }

        if (!map.get(ISSUER).get(0).equals(inboundAuthKey)) {
            validationErrors.add(String.format("The Inbound Auth Key of the  application name %s " +
                    "is not match with SAML issuer %s.", inboundAuthKey, map.get(ISSUER).get(0)));
        }

        if (map.get(ISSUER).get(0).contains("@")) {
            String errorMessage = "\'@\' is a reserved character. Cannot be used for Service Provider Entity ID.";
            validationErrors.add(errorMessage);
        }

        //Have to check whether issuer exists in create or import (POST) operation.
        if (map.containsKey(IS_UPDATE) && (map.get(IS_UPDATE) != null) && map.get(IS_UPDATE).get(0).equals("false")
                && isIssuerExists(issuerWithQualifier, tenantDomain)) {
            if (map.containsKey(ISSUER_QUALIFIER) && (map.get(ISSUER_QUALIFIER) != null)
                    && StringUtils.isNotBlank(map.get(ISSUER_QUALIFIER).get(0))) {
                validationErrors.add(String.format(ISSUER_WITH_ISSUER_QUALIFIER_ALREADY_EXISTS, issuerWithoutQualifier,
                        map.get(ISSUER_QUALIFIER).get(0), tenantDomain));
            } else {
                validationErrors.add(String.format(ISSUER_ALREADY_EXISTS, map.get(ISSUER).get(0), tenantDomain));
            }
        }
    }

    private String[] getSigningAlgorithmUris() {

        Collection<String> uris = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().values();
        return uris.toArray(new String[uris.size()]);
    }

    private String[] getDigestAlgorithmURIs() {

        Collection<String> digestAlgoUris = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().values();
        return digestAlgoUris.toArray(new String[digestAlgoUris.size()]);
    }

    private String[] getAssertionEncryptionAlgorithmURIs() {

        Collection<String> assertionEncryptionAlgoUris =
                IdentityApplicationManagementUtil.getXMLAssertionEncryptionAlgorithms().values();
        return assertionEncryptionAlgoUris.toArray(new String[assertionEncryptionAlgoUris.size()]);
    }

    private String[] getKeyEncryptionAlgorithmURIs() {

        Collection<String> keyEncryptionAlgoUris =
                IdentityApplicationManagementUtil.getXMLKeyEncryptionAlgorithms().values();
        return keyEncryptionAlgoUris.toArray(new String[keyEncryptionAlgoUris.size()]);
    }

    private static IdentitySAML2SSOException handleIOException(Error error, String message, IOException e) {
        return new IdentitySAML2ClientException(error.getErrorCode(), message, e);
    }

    private static int getConnectionTimeoutInMillis() {
        return getHttpConnectionConfigValue("SSOService.SAMLMetadataUrlConnectionTimeout", 5000);
    }

    private static int getReadTimeoutInMillis() {
        return getHttpConnectionConfigValue("SSOService.SAMLMetadataUrlReadTimeout", 5000);
    }

    private static int getMaxSizeInBytes() {
        return getHttpConnectionConfigValue("SSOService.SAMLMetadataUrlResponseMaxSize", 51200);
    }

    private static int getHttpConnectionConfigValue(String xPath, int defaultValue) {
        int configValue = defaultValue;
        String config = IdentityUtil.getProperty(xPath);
        if (StringUtils.isNotBlank(config)) {
            try {
                configValue = Integer.parseInt(config);
            } catch (NumberFormatException var6) {
                logger.error("Provided HTTP connection config value in " + xPath + " should be an integer type. " +
                        "Value : " + config);
            }
        }

        return configValue;
    }

    private static String serializeObjectToString(X509Certificate certificate) throws IOException {
        try {
            ByteArrayOutputStream arrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(arrayOutputStream);
            objectOutputStream.writeObject(certificate);
            objectOutputStream.flush();
            return Base64.getEncoder().encodeToString(arrayOutputStream.toByteArray());
        } catch (IOException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error happened when serializing the certificate.");
            }
            throw new IOException("Error happened when serializing the certificate.", e);
        }
    }

    private static X509Certificate deserializeObjectFromString(String objectString)
            throws IOException, ClassNotFoundException {
        byte[] bytes = Base64.getDecoder().decode(objectString.getBytes());
        ByteArrayInputStream arrayInputStream =
                new ByteArrayInputStream(bytes);
        ObjectInputStream objectInputStream = null;
        try {
            objectInputStream = new ObjectInputStream(arrayInputStream);
            return (X509Certificate) objectInputStream.readObject();
        } catch (IOException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error happened when deserializing the certificate string.");
            }
            throw new IOException("Error happened when deserializing the certificate string.", e);
        } catch (ClassNotFoundException e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Error happened when deserializing the certificate string.");
            }
            throw new ClassNotFoundException("Error happened when deserializing the certificate string.", e);
        }

    }
}
