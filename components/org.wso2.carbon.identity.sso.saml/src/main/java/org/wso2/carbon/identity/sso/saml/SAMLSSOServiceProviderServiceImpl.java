package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public class SAMLSSOServiceProviderServiceImpl implements SAMLSSOServiceProviderService{

    private static final Log log = LogFactory.getLog(SAMLSSOServiceProviderServiceImpl.class);
    private static SAMLSSOServiceProviderServiceImpl samlssoServiceProviderService = new SAMLSSOServiceProviderServiceImpl();
    private ApplicationManagementService applicationManagementService;

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
    private static final String METADATA = "metadata";

    private SAMLSSOServiceProviderServiceImpl() {
        applicationManagementService = SAMLSSOUtil.getApplicationMgtService();
    }

    public static SAMLSSOServiceProviderServiceImpl getInstance() {
        return samlssoServiceProviderService;
    }

    @Override
    public boolean addServiceProvider(SAMLSSOServiceProviderDO serviceProviderDO, String tenantDomain, String userName)
            throws IdentityException {

        ServiceProvider application = new ServiceProvider();
        application.setApplicationName(generateApplicationName());
        application.setInboundAuthenticationConfig(createInboundAuthenticationConfig(serviceProviderDO));
        try {
            String resourceId = applicationManagementService.createApplication(application, tenantDomain, userName);
        } catch (IdentityApplicationManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while creating application: ", e);
            }
            throw new IdentityException("Error while creating application:",e);
        }
        return true;
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
        UUID uuid=UUID.randomUUID();
        return uuid.toString()+"_SAML_SP";
    }

    @Override
    public SAMLSSOServiceProviderDO[] getServiceProviders(String tenantDomain, String userName)
            throws IdentityException {
        return new SAMLSSOServiceProviderDO[0];
    }

    @Override
    public boolean removeServiceProvider(String issuer, String tenantDomain, String userName)
            throws IdentityException {
        return false;
    }

    @Override
    public SAMLSSOServiceProviderDO getServiceProvider(String issuer, String tenantDomain, String userName)
            throws IdentityException {
        return null;
    }

    @Override
    public boolean isServiceProviderExists(String issuer, String tenantDomain, String userName)
            throws IdentityException {
        return false;
    }
}
