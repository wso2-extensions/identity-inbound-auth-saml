package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.CertificateRetriever;
import org.wso2.carbon.identity.core.CertificateRetrievingException;
import org.wso2.carbon.identity.core.DatabaseCertificateRetriever;
import org.wso2.carbon.identity.core.KeyStoreCertificateRetriever;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.user.api.Tenant;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import java.util.stream.Collectors;

import static org.wso2.carbon.identity.core.util.JdbcUtils.isH2DB;

/**
 * This class is used for managing SAML SSO providers. Adding, retrieving and removing service
 * providers are supported here.
 */
public class SAMLSSOServiceProviderServiceImpl implements SAMLSSOServiceProviderService {

    private static final Log log = LogFactory.getLog(SAMLSSOServiceProviderServiceImpl.class);
    private static SAMLSSOServiceProviderServiceImpl samlssoServiceProviderService =
            new SAMLSSOServiceProviderServiceImpl();
    private ApplicationManagementService applicationManagementService;
    public static final String SAMLSSO = "samlsso";
    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID = "SELECT " +
            "META.VALUE FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 = "SELECT " +
            "META.`VALUE` FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private SAMLSSOServiceProviderServiceImpl() {
        applicationManagementService = SAMLSSOUtil.getApplicationMgtService();
    }

    public static SAMLSSOServiceProviderServiceImpl getInstance() {
        return samlssoServiceProviderService;
    }

    @Override
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO)
            throws IdentityException {
        ServiceProvider application = new ServiceProvider();
        application.setApplicationName(generateApplicationName());

        if (serviceProviderDO.getNameIDFormat() == null) {
            serviceProviderDO.setNameIDFormat(NameIdentifier.UNSPECIFIED);
        } else {
            serviceProviderDO.setNameIDFormat(serviceProviderDO.getNameIDFormat().replace("/", ":"));
        }

        application.setInboundAuthenticationConfig(createInboundAuthenticationConfig(serviceProviderDO));
        String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            String resourceId = applicationManagementService.createApplication(application, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while creating application.", e);
            }
            throw new IdentityException("Error while creating application.", e);
        }
        return true;
    }

    @Override
    public SAMLSSOServiceProviderDO[] getServiceProviders() throws IdentityException {

        HashMap<String, List<Property>> propertyMap = new HashMap<>();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            propertyMap = applicationManagementService.getAllInboundAuthenticationPropertiesByClientType(SAMLSSO,
                    tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException(String.format("Error happened when retrieving SAML Service" +
                    " Provider Information in tenantDomain: %s.", tenantDomain), e);
        }
        SAMLSSOServiceProviderDO[] samlssoServiceProviderDOS = new SAMLSSOServiceProviderDO[propertyMap.size()];
        int index = 0;
        for (String key: propertyMap.keySet()) {
            Property[] properties = propertyMap.get(key).toArray(new Property[0]);
            SAMLSSOServiceProviderDO serviceProviderDO = getServiceProviderDO(properties);
            serviceProviderDO.setTenantDomain(tenantDomain);
            samlssoServiceProviderDOS[index++] = serviceProviderDO;
        }
        return samlssoServiceProviderDOS;
    }

    @Override
    public boolean removeServiceProvider(String issuer) throws IdentityException {
        if (issuer == null || issuer.equals("default")) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Issuer name can't be : %s.", issuer));
            }
            return false;
        }
        ServiceProvider serviceProvider = null;
        String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            serviceProvider = applicationManagementService.getServiceProviderByClientId(issuer, SAMLSSO , tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException(String.format("Error happened when retrieving Service" +
                    " Provider Information for the saml issuer: %s in tenantDomain: %s .", issuer, tenantDomain), e);
        }
        if (serviceProvider == null || serviceProvider.getApplicationName().equals("default")) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Couldn't find an application with the issuer name: %s.", issuer));
            }
            return false;
        }
        ServiceProvider appToUpdate = null;
        try {
            appToUpdate = deepCopyApplication(serviceProvider);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException("Error while cloning the Service Provider object.", e);
        }

        InboundAuthenticationConfig inboundAuthenticationConfig = appToUpdate.getInboundAuthenticationConfig();
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(Arrays.stream(appToUpdate
                .getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs())
                .filter(config -> !config.getInboundAuthType().equals(SAMLSSO))
                .toArray(InboundAuthenticationRequestConfig[]::new));
        appToUpdate.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        try {
            applicationManagementService.updateApplication(appToUpdate, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException(String.format("Error happened when updating Service" +
                    " Provider Information for the saml issuer: %s in tenantDomain: %s .", issuer, tenantDomain), e);
        }
        return true;
    }

    @Override
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer, int tenantId)
            throws IdentityException {
        ServiceProvider serviceProvider = null;
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            serviceProvider = applicationManagementService.getServiceProviderByClientId(issuer, SAMLSSO , tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException(String.format("Error happened when retrieving Service" +
                    " Provider Information for the saml issuer: %s in tenantDomain: %s .", issuer, tenantDomain), e);
        }

        if (serviceProvider == null || serviceProvider.getApplicationName().equals("default")) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Couldn't find an application with the issuer name: %s.", issuer));
            }
            return null;
        }

        if (serviceProvider.getInboundAuthenticationConfig() != null
                && serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {
            for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authConfig.getInboundAuthType(), SAMLSSO)) {
                    if (authConfig.getProperties() != null) {
                        SAMLSSOServiceProviderDO serviceProviderDO = getServiceProviderDO(authConfig.getProperties());

                        // Load the certificate stored in the database, if signature validation is enabled.
                        if (serviceProviderDO.isDoValidateSignatureInRequests() ||
                                serviceProviderDO.isDoValidateSignatureInArtifactResolve() ||
                                serviceProviderDO.isDoEnableEncryptedAssertion()) {
                            Tenant tenant = new Tenant();
                            tenant.setDomain(tenantDomain);
                            tenant.setId(tenantId);
                            try {
                                serviceProviderDO.setX509Certificate(getApplicationCertificate(serviceProviderDO,
                                        tenant));
                            } catch (SQLException e) {
                                throw new IdentityException(String.format("An error occurred while getting the " +
                                        "application certificate id for validating the requests from the issuer '%s'",
                                        issuer), e);
                            } catch (CertificateRetrievingException e) {
                                throw new IdentityException(String.format("An error occurred while getting the " +
                                        "application certificate for validating the requests from the issuer '%s'",
                                        issuer), e);
                            }
                        }
                        serviceProviderDO.setTenantDomain(tenantDomain);
                        return serviceProviderDO;
                    }
                }
            }
        }
        return null;
    }

    @Override
    public boolean isServiceProviderExists(String issuer)
            throws IdentityException {
        String serviceProviderName = null;
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            serviceProviderName = applicationManagementService.getServiceProviderNameByClientId(issuer, SAMLSSO,
                    tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            throw new IdentityException(String.format("Error happened when retrieving Service" +
                    " Provider Name for the saml issuer: %s in tenantDomain: %s .", issuer, tenantDomain), e);
        }
        return serviceProviderName != null && !serviceProviderName.equals("default");
    }

    private InboundAuthenticationConfig createInboundAuthenticationConfig(SAMLSSOServiceProviderDO serviceProviderDO) {
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();

        InboundAuthenticationRequestConfig samlInbound = new InboundAuthenticationRequestConfig();
        samlInbound.setInboundAuthType(FrameworkConstants.StandardInboundProtocols.SAML2);
        samlInbound.setInboundAuthKey(serviceProviderDO.getIssuer());

        List<Property> propertyList = new ArrayList<>();
        addSAMLInboundProperties(propertyList, serviceProviderDO);
        Property[] properties = propertyList.toArray(new Property[0]);
        samlInbound.setProperties(properties);

        InboundAuthenticationRequestConfig[] requestConfigs = new InboundAuthenticationRequestConfig[1];
        requestConfigs[0] = samlInbound;
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(requestConfigs);
        return inboundAuthenticationConfig;
    }

    private void addSAMLInboundProperties(List<Property> propertyList,
                                    SAMLSSOServiceProviderDO serviceProviderDO) {
        addKeyValuePair(SAMLSSOConstants.Metadata.ISSUER, serviceProviderDO.getIssuer(), propertyList);
        for (String url : serviceProviderDO.getAssertionConsumerUrls()) {
            addKeyValuePair(SAMLSSOConstants.Metadata.ASSERTION_CONSUMER_URLS, url, propertyList);
        }
        addKeyValuePair(SAMLSSOConstants.Metadata.DEFAULT_ASSERTION_CONSUMER_URL,
                serviceProviderDO.getDefaultAssertionConsumerUrl(), propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.ISSUER_CERT_ALIAS, serviceProviderDO.getCertAlias(), propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.LOGIN_PAGE_URL, serviceProviderDO.getLoginPageURL(), propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.NAME_ID_FORMAT, serviceProviderDO.getNameIDFormat(), propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.SIGNING_ALGORITHM, serviceProviderDO.getSigningAlgorithmUri(),
                propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.DIGEST_ALGORITHM, serviceProviderDO.getDigestAlgorithmUri(),
                propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.ASSERTION_ENCRYPTION_ALGORITHM,
                serviceProviderDO.getAssertionEncryptionAlgorithmUri(), propertyList);
        addKeyValuePair(SAMLSSOConstants.Metadata.KEY_ENCRYPTION_ALGORITHM,
                serviceProviderDO.getKeyEncryptionAlgorithmUri(), propertyList);
        if (serviceProviderDO.getNameIdClaimUri() != null
                && serviceProviderDO.getNameIdClaimUri().trim().length() > 0) {
            addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_NAME_ID_CLAIM_URI, "true", propertyList);
            addKeyValuePair(SAMLSSOConstants.Metadata.NAME_ID_CLAIM_URI, serviceProviderDO.getNameIdClaimUri(),
                    propertyList);
        } else {
            addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_NAME_ID_CLAIM_URI, "false", propertyList);
        }

        String doSingleLogout = String.valueOf(serviceProviderDO.isDoSingleLogout());
        addKeyValuePair(SAMLSSOConstants.Metadata.DO_SINGLE_LOGOUT, doSingleLogout, propertyList);
        if (serviceProviderDO.isDoSingleLogout()) {
            if (StringUtils.isNotBlank(serviceProviderDO.getSloResponseURL())) {
                addKeyValuePair(SAMLSSOConstants.Metadata.SLO_RESPONSE_URL, serviceProviderDO.getSloResponseURL(),
                        propertyList);
            }
            if (StringUtils.isNotBlank(serviceProviderDO.getSloRequestURL())) {
                addKeyValuePair(SAMLSSOConstants.Metadata.SLO_REQUEST_URL, serviceProviderDO.getSloRequestURL(),
                        propertyList);
            }
            // Create doFrontChannelLogout property in the registry.
            String doFrontChannelLogout = String.valueOf(serviceProviderDO.isDoFrontChannelLogout());
            addKeyValuePair(SAMLSSOConstants.Metadata.DO_FRONT_CHANNEL_LOGOUT, doFrontChannelLogout, propertyList);
            if (serviceProviderDO.isDoFrontChannelLogout()) {
                // Create frontChannelLogoutMethod property in the registry.
                addKeyValuePair(SAMLSSOConstants.Metadata.FRONT_CHANNEL_LOGOUT_BINDING,
                        serviceProviderDO.getFrontChannelLogoutBinding(), propertyList);
            }
        }

        String doSignResponse = String.valueOf(serviceProviderDO.isDoSignResponse());
        addKeyValuePair(SAMLSSOConstants.Metadata.DO_SIGN_RESPONSE, doSignResponse, propertyList);

        String isAssertionQueryRequestProfileEnabled = String.valueOf(serviceProviderDO
                .isAssertionQueryRequestProfileEnabled());
        addKeyValuePair(SAMLSSOConstants.Metadata.ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                isAssertionQueryRequestProfileEnabled, propertyList);

        String supportedAssertionQueryRequestTypes = serviceProviderDO.getSupportedAssertionQueryRequestTypes();
        addKeyValuePair(SAMLSSOConstants.Metadata.SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                supportedAssertionQueryRequestTypes, propertyList);

        String isEnableSAML2ArtifactBinding = String.valueOf(serviceProviderDO.isEnableSAML2ArtifactBinding());
        addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_SAML2_ARTIFACT_BINDING, isEnableSAML2ArtifactBinding,
                propertyList);

        String doSignAssertions = String.valueOf(serviceProviderDO.isDoSignAssertions());
        addKeyValuePair(SAMLSSOConstants.Metadata.DO_SIGN_ASSERTIONS, doSignAssertions, propertyList);

        String isSamlECP = String.valueOf(serviceProviderDO.isSamlECP());
        addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_ECP, isSamlECP, propertyList);

        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedClaimsList())) {
            for (String requestedClaim : serviceProviderDO.getRequestedClaimsList()) {
                addKeyValuePair(SAMLSSOConstants.Metadata.REQUESTED_CLAIMS, requestedClaim, propertyList);
            }
        }

        addKeyValuePair(SAMLSSOConstants.Metadata.ATTRIBUTE_CONSUMING_SERVICE_INDEX,
                serviceProviderDO.getAttributeConsumingServiceIndex(), propertyList);

        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedAudiencesList())) {
            for (String requestedAudience : serviceProviderDO.getRequestedAudiencesList()) {
                addKeyValuePair(SAMLSSOConstants.Metadata.REQUESTED_AUDIENCES, requestedAudience, propertyList);
            }
        }
        if (CollectionUtils.isNotEmpty(serviceProviderDO.getRequestedRecipientsList())) {
            for (String requestedRecipient : serviceProviderDO.getRequestedRecipientsList()) {
                addKeyValuePair(SAMLSSOConstants.Metadata.REQUESTED_RECIPIENTS, requestedRecipient, propertyList);
            }
        }

        String enableAttributesByDefault = String.valueOf(serviceProviderDO.isEnableAttributesByDefault());
        addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_ATTRIBUTES_BY_DEFAULT, enableAttributesByDefault,
                propertyList);

        String idPInitSSOEnabled = String.valueOf(serviceProviderDO.isIdPInitSSOEnabled());
        addKeyValuePair(SAMLSSOConstants.Metadata.IDP_INIT_SSO_ENABLED, idPInitSSOEnabled, propertyList);

        String idPInitSLOEnabled = String.valueOf(serviceProviderDO.isIdPInitSLOEnabled());
        addKeyValuePair(SAMLSSOConstants.Metadata.IDP_INIT_SLO_ENABLED, idPInitSLOEnabled, propertyList);

        if (serviceProviderDO.isIdPInitSLOEnabled() && serviceProviderDO.getIdpInitSLOReturnToURLList().size() > 0) {
            for (String sloReturnUrl : serviceProviderDO.getIdpInitSLOReturnToURLList()) {
                addKeyValuePair(SAMLSSOConstants.Metadata.IDP_INIT_SLO_RETURN_URLS, sloReturnUrl, propertyList);
            }
        }
        String enableEncryptedAssertion = String.valueOf(serviceProviderDO.isDoEnableEncryptedAssertion());
        addKeyValuePair(SAMLSSOConstants.Metadata.ENABLE_ENCRYPTED_ASSERTION, enableEncryptedAssertion, propertyList);

        String validateSignatureInRequests = String.valueOf(serviceProviderDO.isDoValidateSignatureInRequests());
        addKeyValuePair(SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_REQUESTS, validateSignatureInRequests,
                propertyList);

        String validateSignatureInArtifactResolve =
                String.valueOf(serviceProviderDO.isDoValidateSignatureInArtifactResolve());
        addKeyValuePair(SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                validateSignatureInArtifactResolve, propertyList);

        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            addKeyValuePair(SAMLSSOConstants.Metadata.ISSUER_QUALIFIER, serviceProviderDO.getIssuerQualifier(),
                    propertyList);
        }
        if (StringUtils.isNotBlank(serviceProviderDO.getIdpEntityIDAlias())) {
            addKeyValuePair(SAMLSSOConstants.Metadata.IDP_ENTITY_ID_ALIAS, serviceProviderDO.getIdpEntityIDAlias(),
                    propertyList);
        }

        addKeyValuePair(SAMLSSOConstants.Metadata.IS_UPDATE, "false", propertyList);
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

    private String generateApplicationName() {
        UUID uuid = UUID.randomUUID();
        return uuid.toString() + "_SAML-SP";
    }

    private SAMLSSOServiceProviderDO getServiceProviderDO(Property[] properties) {
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));

        SAMLSSOServiceProviderDO serviceProviderDO = new SAMLSSOServiceProviderDO();
        serviceProviderDO.setIssuer(getSingleValue(map, SAMLSSOConstants.Metadata.ISSUER));

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ISSUER_QUALIFIER) != null) {
            serviceProviderDO.setIssuerQualifier(getSingleValue(map, SAMLSSOConstants.Metadata.ISSUER_QUALIFIER));
        }

        serviceProviderDO.setAssertionConsumerUrls(getMultiValues(map,
                SAMLSSOConstants.Metadata.ASSERTION_CONSUMER_URLS));
        serviceProviderDO.setDefaultAssertionConsumerUrl(getSingleValue(map,
                SAMLSSOConstants.Metadata.DEFAULT_ASSERTION_CONSUMER_URL));
        serviceProviderDO.setCertAlias(getSingleValue(map, SAMLSSOConstants.Metadata.ISSUER_CERT_ALIAS));

        if (StringUtils.isNotEmpty(getSingleValue(map, SAMLSSOConstants.Metadata.SIGNING_ALGORITHM))) {
            serviceProviderDO.setSigningAlgorithmUri(getSingleValue(map, SAMLSSOConstants.Metadata.SIGNING_ALGORITHM));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ASSERTION_QUERY_REQUEST_PROFILE_ENABLED) != null) {
            serviceProviderDO.setAssertionQueryRequestProfileEnabled(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ASSERTION_QUERY_REQUEST_PROFILE_ENABLED).trim()));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES) != null) {
            serviceProviderDO.setSupportedAssertionQueryRequestTypes(getSingleValue(map,
                    SAMLSSOConstants.Metadata.SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES).trim());
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_SAML2_ARTIFACT_BINDING) != null) {
            serviceProviderDO.setEnableSAML2ArtifactBinding(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ENABLE_SAML2_ARTIFACT_BINDING).trim()));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, SAMLSSOConstants.Metadata.DIGEST_ALGORITHM))) {
            serviceProviderDO.setDigestAlgorithmUri(getSingleValue(map, SAMLSSOConstants.Metadata.DIGEST_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, SAMLSSOConstants.Metadata.ASSERTION_ENCRYPTION_ALGORITHM))) {
            serviceProviderDO.setAssertionEncryptionAlgorithmUri(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ASSERTION_ENCRYPTION_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, SAMLSSOConstants.Metadata.KEY_ENCRYPTION_ALGORITHM))) {
            serviceProviderDO.setKeyEncryptionAlgorithmUri(getSingleValue(map,
                    SAMLSSOConstants.Metadata.KEY_ENCRYPTION_ALGORITHM));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.DO_SINGLE_LOGOUT) != null) {
            serviceProviderDO.setDoSingleLogout(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.DO_SINGLE_LOGOUT).trim()));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.NAME_ID_FORMAT) != null) {
            serviceProviderDO.setNameIDFormat(getSingleValue(map, SAMLSSOConstants.Metadata.NAME_ID_FORMAT));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_NAME_ID_CLAIM_URI) != null) {
            if (Boolean.parseBoolean(getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_NAME_ID_CLAIM_URI).trim())) {
                serviceProviderDO.setNameIdClaimUri(getSingleValue(map, SAMLSSOConstants.Metadata.NAME_ID_CLAIM_URI));
            }
        }

        serviceProviderDO.setLoginPageURL(getSingleValue(map, SAMLSSOConstants.Metadata.LOGIN_PAGE_URL));

        if (getSingleValue(map, SAMLSSOConstants.Metadata.DO_SIGN_RESPONSE) != null) {
            serviceProviderDO.setDoSignResponse(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.DO_SIGN_RESPONSE).trim()));
        }

        if (serviceProviderDO.isDoSingleLogout()) {
            serviceProviderDO.setSloResponseURL(getSingleValue(map, SAMLSSOConstants.Metadata.SLO_RESPONSE_URL));
            serviceProviderDO.setSloRequestURL(getSingleValue(map, SAMLSSOConstants.Metadata.SLO_REQUEST_URL));
            // Check front channel logout enable.
            if (getSingleValue(map, SAMLSSOConstants.Metadata.DO_FRONT_CHANNEL_LOGOUT) != null) {
                serviceProviderDO.setDoFrontChannelLogout(Boolean.parseBoolean(getSingleValue(map,
                        SAMLSSOConstants.Metadata.DO_FRONT_CHANNEL_LOGOUT).trim()));
                if (serviceProviderDO.isDoFrontChannelLogout()) {
                    if (getSingleValue(map, SAMLSSOConstants.Metadata.FRONT_CHANNEL_LOGOUT_BINDING) != null) {
                        serviceProviderDO.setFrontChannelLogoutBinding(getSingleValue(map,
                                SAMLSSOConstants.Metadata.FRONT_CHANNEL_LOGOUT_BINDING));
                    } else {
                        // Default is redirect-binding.
                        serviceProviderDO.setFrontChannelLogoutBinding(
                                SAMLSSOConstants.Metadata.DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING);
                    }

                }
            }
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.DO_SIGN_ASSERTIONS) != null) {
            serviceProviderDO.setDoSignAssertions(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.DO_SIGN_ASSERTIONS).trim()));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_ECP) != null) {
            serviceProviderDO.setSamlECP(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ENABLE_ECP).trim()));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ATTRIBUTE_CONSUMING_SERVICE_INDEX) != null) {
            serviceProviderDO.setAttributeConsumingServiceIndex(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ATTRIBUTE_CONSUMING_SERVICE_INDEX));
        } else {
            // Specific DB's (like oracle) returns empty strings as null.
            serviceProviderDO.setAttributeConsumingServiceIndex("");
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.REQUESTED_CLAIMS) != null) {
            serviceProviderDO.setRequestedClaims(getMultiValues(map, SAMLSSOConstants.Metadata.REQUESTED_CLAIMS));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.REQUESTED_AUDIENCES) != null) {
            serviceProviderDO.setRequestedAudiences(getMultiValues(map, SAMLSSOConstants.Metadata.REQUESTED_AUDIENCES));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.REQUESTED_RECIPIENTS) != null) {
            serviceProviderDO.setRequestedRecipients(getMultiValues(map,
                    SAMLSSOConstants.Metadata.REQUESTED_RECIPIENTS));
        }

        if (getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_ATTRIBUTES_BY_DEFAULT) != null) {
            String enableAttrByDefault = getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_ATTRIBUTES_BY_DEFAULT);
            serviceProviderDO.setEnableAttributesByDefault(Boolean.parseBoolean(enableAttrByDefault));
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.IDP_INIT_SSO_ENABLED) != null) {
            serviceProviderDO.setIdPInitSSOEnabled(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.IDP_INIT_SSO_ENABLED).trim()));
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.IDP_INIT_SLO_ENABLED) != null) {
            serviceProviderDO.setIdPInitSLOEnabled(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.IDP_INIT_SLO_ENABLED).trim()));
            if (serviceProviderDO.isIdPInitSLOEnabled() && getSingleValue(map,
                    SAMLSSOConstants.Metadata.IDP_INIT_SLO_RETURN_URLS) != null) {
                serviceProviderDO.setIdpInitSLOReturnToURLs(getMultiValues(map,
                        SAMLSSOConstants.Metadata.IDP_INIT_SLO_RETURN_URLS));
            }
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.ENABLE_ENCRYPTED_ASSERTION) != null) {
            serviceProviderDO.setDoEnableEncryptedAssertion(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.ENABLE_ENCRYPTED_ASSERTION).trim()));
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_REQUESTS) != null) {
            serviceProviderDO.setDoValidateSignatureInRequests(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_REQUESTS).trim()));
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE) != null) {
            serviceProviderDO.setDoValidateSignatureInArtifactResolve(Boolean.parseBoolean(getSingleValue(map,
                    SAMLSSOConstants.Metadata.VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE).trim()));
        }
        if (getSingleValue(map, SAMLSSOConstants.Metadata.IDP_ENTITY_ID_ALIAS) != null) {
            serviceProviderDO.setIdpEntityIDAlias(getSingleValue(map, SAMLSSOConstants.Metadata.IDP_ENTITY_ID_ALIAS));
        }
        return serviceProviderDO;
    }

    private static String[] getMultiValues(HashMap<String, List<String>> map, String key) {
        if (key != null && map.containsKey(key) && map.get(key) != null) {
            return map.get(key).toArray(new String[0]);
        }
        return new String[0];
    }

    private static String getSingleValue(HashMap<String, List<String>> map, String key) {
        if (key != null && map.containsKey(key) && map.get(key) != null) {
            return map.get(key).get(0);
        }
        return null;
    }

    private static ServiceProvider deepCopyApplication(ServiceProvider application)
            throws IdentityApplicationManagementException {

        ObjectOutputStream objOutPutStream;
        ObjectInputStream objInputStream;
        ServiceProvider newObject;
        try {
            ByteArrayOutputStream byteArrayOutPutStream = new ByteArrayOutputStream();
            objOutPutStream = new ObjectOutputStream(byteArrayOutPutStream);
            objOutPutStream.writeObject(application);

            ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(byteArrayOutPutStream.toByteArray());
            objInputStream = new ObjectInputStream(byteArrayInputStream);
            newObject = (ServiceProvider) objInputStream.readObject();
        } catch (ClassNotFoundException | IOException e) {
            throw new IdentityApplicationManagementException("Error deep cloning Service Provider object.", e);
        }
        return newObject;
    }

    /**
     * Returns the {@link java.security.cert.Certificate} which should used to validate the requests
     * for the given service provider.
     *
     * @param serviceProviderDO
     * @param tenant
     * @return
     * @throws SQLException
     * @throws CertificateRetrievingException
     */
    private X509Certificate getApplicationCertificate(SAMLSSOServiceProviderDO serviceProviderDO, Tenant tenant)
            throws SQLException, CertificateRetrievingException {

        // Check whether there is a certificate stored against the service provider (in the database)
        int applicationCertificateId = getApplicationCertificateId(serviceProviderDO.getIssuer(), tenant.getId());

        CertificateRetriever certificateRetriever;
        String certificateIdentifier;
        if (applicationCertificateId != -1) {
            certificateRetriever = new DatabaseCertificateRetriever();
            certificateIdentifier = Integer.toString(applicationCertificateId);
        } else {
            certificateRetriever = new KeyStoreCertificateRetriever();
            certificateIdentifier = serviceProviderDO.getCertAlias();
        }

        return certificateRetriever.getCertificate(certificateIdentifier, tenant);
    }

    /**
     * Returns the certificate reference ID for the given issuer (Service Provider) if there is one.
     *
     * @param issuer
     * @return
     * @throws SQLException
     */
    private int getApplicationCertificateId(String issuer, int tenantId) throws SQLException {

        try {
            String sqlStmt = isH2DB() ? QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 :
                    QUERY_TO_GET_APPLICATION_CERTIFICATE_ID;
            try (Connection connection = IdentityDatabaseUtil.getDBConnection(false);
                 PreparedStatement statementToGetApplicationCertificate =
                         connection.prepareStatement(sqlStmt)) {
                statementToGetApplicationCertificate.setString(1, SAMLSSOConstants.Metadata.CERTIFICATE);
                statementToGetApplicationCertificate.setString(2, issuer);
                statementToGetApplicationCertificate.setInt(3, tenantId);

                try (ResultSet queryResults = statementToGetApplicationCertificate.executeQuery()) {
                    if (queryResults.next()) {
                        return queryResults.getInt(1);
                    }
                }
            }
            return -1;
        } catch (DataAccessException e) {
            String errorMsg = "Error while retrieving application certificate data for issuer: " + issuer +
                    " and tenant Id: " + tenantId;
            throw new SQLException(errorMsg, e);
        }
    }
}
