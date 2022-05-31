package org.wso2.carbon.identity.sso.saml;

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

    private static final String CERTIFICATE_PROPERTY_NAME = "CERTIFICATE";
    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID = "SELECT " +
            "META.VALUE FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static final String QUERY_TO_GET_APPLICATION_CERTIFICATE_ID_H2 = "SELECT " +
            "META.`VALUE` FROM SP_INBOUND_AUTH INBOUND, SP_APP SP, SP_METADATA META WHERE SP.ID = INBOUND.APP_ID AND " +
            "SP.ID = META.SP_ID AND META.NAME = ? AND INBOUND.INBOUND_AUTH_KEY = ? AND META.TENANT_ID = ?";

    private static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attrConsumServiceIndex";

    private static final String ISSUER = "issuer";
    private static final String ISSUER_QUALIFIER = "issuerQualifier";
    private static final String ASSERTION_CONSUMER_URLS = "assertionConsumerUrls";
    private static final String DEFAULT_ASSERTION_CONSUMER_URL = "defaultAssertionConsumerUrl";
    private static final String SIGNING_ALGORITHM_URI = "signingAlgorithmURI";
    private static final String DIGEST_ALGORITHM_URI = "digestAlgorithmURI";
    private static final String ASSERTION_ENCRYPTION_ALGORITHM_URI = "assertionEncryptionAlgorithmURI";
    private static final String KEY_ENCRYPTION_ALGORITHM_URI = "keyEncryptionAlgorithmURI";
    private static final String CERT_ALIAS = "certAlias";
    private static final String DO_SIGN_RESPONSE = "doSignResponse";
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
    private static final String SAMLSSO = "samlsso";

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
        application.setInboundAuthenticationConfig(createInboundAuthenticationConfig(serviceProviderDO));
        String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        try {
            String resourceId = applicationManagementService.createApplication(application, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while creating application: ", e);
            }
            throw new IdentityException("Error while creating application:", e);
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
                    " Provider Information in tenantDomain: %s .", tenantDomain), e);
        }
        SAMLSSOServiceProviderDO[] samlssoServiceProviderDOS = new SAMLSSOServiceProviderDO[propertyMap.size()];
        int index = 0;
        for (String key: propertyMap.keySet()) {
            Property[] properties = propertyMap.get(key).toArray(new Property[0]);
            SAMLSSOServiceProviderDO serviceProviderDO = getServiceProviderDO(properties);
            samlssoServiceProviderDOS[index++] = serviceProviderDO;
        }
        return samlssoServiceProviderDOS;
    }

    @Override
    public boolean removeServiceProvider(String issuer) throws IdentityException {
        if (issuer == null || issuer.equals("default")) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Issuer name can't be : %s.",issuer));
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
                log.debug(String.format("Couldn't find an application with the issuer name: %s.",issuer));
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
                log.debug(String.format("Couldn't find an application with the issuer name: %s.",issuer));
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

                        // Load the certificate stored in the database, if signature validation is enabled..
                        if (serviceProviderDO.isDoValidateSignatureInRequests() ||
                                serviceProviderDO.isDoValidateSignatureInArtifactResolve() ||
                                serviceProviderDO.isDoEnableEncryptedAssertion()) {
                            Tenant tenant = new Tenant();
                            tenant.setDomain(tenantDomain);
                            tenant.setId(tenantId);
                            try {
                                serviceProviderDO.setX509Certificate(getApplicationCertificate(serviceProviderDO, tenant));
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
        addKeyValuePair(ATTRIBUTE_CONSUMING_SERVICE_INDEX, serviceProviderDO.getAttributeConsumingServiceIndex(),
                propertyList);
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
        addKeyValuePair(IS_UPDATE, "false", propertyList);
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
        serviceProviderDO.setIssuer(getSingleValue(map, ISSUER));
        serviceProviderDO.setIssuerQualifier(getSingleValue(map, ISSUER_QUALIFIER));
        if (StringUtils.isNotBlank(serviceProviderDO.getIssuerQualifier())) {
            serviceProviderDO.setIssuer(SAMLSSOUtil.getIssuerWithoutQualifier(serviceProviderDO.getIssuer()));
        }
        serviceProviderDO.setAssertionConsumerUrls(getMultiValues(map, ASSERTION_CONSUMER_URLS));

        serviceProviderDO.setDefaultAssertionConsumerUrl(getSingleValue(map, DEFAULT_ASSERTION_CONSUMER_URL));
        serviceProviderDO.setSigningAlgorithmUri(getSingleValue(map, SIGNING_ALGORITHM_URI));
        serviceProviderDO.setDigestAlgorithmUri(getSingleValue(map, DIGEST_ALGORITHM_URI));
        serviceProviderDO.setAssertionEncryptionAlgorithmUri(getSingleValue(map, ASSERTION_ENCRYPTION_ALGORITHM_URI));
        serviceProviderDO.setKeyEncryptionAlgorithmUri(getSingleValue(map, KEY_ENCRYPTION_ALGORITHM_URI));
        serviceProviderDO.setCertAlias(getSingleValue(map, CERT_ALIAS));
        serviceProviderDO.setAttributeConsumingServiceIndex(getSingleValue(map, ATTRIBUTE_CONSUMING_SERVICE_INDEX));

        serviceProviderDO.setDoSignResponse(Boolean.parseBoolean(getSingleValue(map, DO_SIGN_RESPONSE)));
                /*
                According to the spec, "The <Assertion> element(s) in the <Response> MUST be signed". Therefore we
                should not reply on any property to decide this behaviour. Hence the property is set to sign by default.
                */
        serviceProviderDO.setDoSignAssertions(true);
        serviceProviderDO.setDoSingleLogout(Boolean.parseBoolean(getSingleValue(map, DO_SINGLE_LOGOUT)));
        serviceProviderDO.setDoFrontChannelLogout(Boolean.parseBoolean(getSingleValue(map, DO_FRONT_CHANNEL_LOGOUT)));
        serviceProviderDO.setFrontChannelLogoutBinding(getSingleValue(map, FRONT_CHANNEL_LOGOUT_BINDING));
        serviceProviderDO.setAssertionQueryRequestProfileEnabled(Boolean.parseBoolean(
                getSingleValue(map, IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED)));
        serviceProviderDO.setSupportedAssertionQueryRequestTypes(
                getSingleValue(map, SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES));
        serviceProviderDO.setEnableSAML2ArtifactBinding(Boolean.parseBoolean(
                getSingleValue(map, ENABLE_SAML2_ARTIFACT_BINDING)));
        serviceProviderDO.setDoValidateSignatureInArtifactResolve(
                Boolean.parseBoolean(getSingleValue(map, DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE)));

        if (!map.containsKey(LOGIN_PAGE_URL) || map.get(LOGIN_PAGE_URL).get(0) == null
                || "null".equals(map.get(LOGIN_PAGE_URL).get(0))) {
            serviceProviderDO.setLoginPageURL("");
        } else {
            serviceProviderDO.setLoginPageURL(getSingleValue(map, LOGIN_PAGE_URL));
        }

        serviceProviderDO.setSloResponseURL(getSingleValue(map, SLO_RESPONSE_URL));
        serviceProviderDO.setSloRequestURL(getSingleValue(map, SLO_REQUEST_URL));
        serviceProviderDO.setRequestedClaims(getMultiValues(map, REQUESTED_CLAIMS));
        serviceProviderDO.setRequestedAudiences(getMultiValues(map, REQUESTED_AUDIENCES));
        serviceProviderDO.setRequestedRecipients(getMultiValues(map, REQUESTED_RECIPIENTS));
        serviceProviderDO.setEnableAttributesByDefault(Boolean.parseBoolean(
                getSingleValue(map, ENABLE_ATTRIBUTES_BY_DEFAULT)));
        serviceProviderDO.setNameIdClaimUri(getSingleValue(map, NAME_ID_CLAIM_URI));
        serviceProviderDO.setNameIDFormat(getSingleValue(map, NAME_ID_FORMAT));

        if (serviceProviderDO.getNameIDFormat() == null) {
            serviceProviderDO.setNameIDFormat(NameIdentifier.UNSPECIFIED);
        }
        serviceProviderDO.setNameIDFormat(serviceProviderDO.getNameIDFormat().replace(":", "/"));

        serviceProviderDO.setIdPInitSSOEnabled(Boolean.parseBoolean(getSingleValue(map, IDP_INIT_SSO_ENABLED)));
        serviceProviderDO.setIdPInitSLOEnabled(Boolean.parseBoolean(getSingleValue(map, IDP_INIT_SLO_ENABLED)));
        serviceProviderDO.setIdpInitSLOReturnToURLs(getMultiValues(map, IDP_INIT_SLO_RETURN_TO_URLS));
        serviceProviderDO.setDoEnableEncryptedAssertion(Boolean.parseBoolean(
                getSingleValue(map, DO_ENABLE_ENCRYPTED_ASSERTION)));
        serviceProviderDO.setDoValidateSignatureInRequests(Boolean.parseBoolean(
                getSingleValue(map, DO_VALIDATE_SIGNATURE_IN_REQUESTS)));
        serviceProviderDO.setIdpEntityIDAlias(getSingleValue(map, IDP_ENTITY_ID_ALIAS));
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
                statementToGetApplicationCertificate.setString(1, CERTIFICATE_PROPERTY_NAME);
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
