/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */
package org.wso2.carbon.identity.sso.saml.internal;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.StandardInboundProtocols;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementValidationException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConfigService;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.Registry;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

/**
 * Application listener responsible for SAML inbound configurations.
 */
public class SAMLApplicationMgtListener extends AbstractApplicationMgtListener {

    private static final Log log = LogFactory.getLog(SAMLApplicationMgtListener.class);
    public static final String SAMLSSO = "samlsso";

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

    @Override
    public int getDefaultOrderId() {
        // Since we are deleting SAML data in pre delete operation, we want this listener to be executed as
        // late as possible allowing other listeners to execute and break the flow if required.
        return 900;
    }

    private void handleSAMLInboundAssociationRemoval(ServiceProvider sp) throws IdentityApplicationManagementException {

        // Get the stored app.
        int appId = sp.getApplicationID();

        ServiceProvider storedSp = SAMLSSOUtil.getApplicationMgtService().getServiceProvider(appId);

        String storedSAMLIssuer = getSAMLIssuer(storedSp);
        String updatedSAMLIssuer = getSAMLIssuer(sp);

        if (isSAMLInboundAssociationRemoved(storedSAMLIssuer, updatedSAMLIssuer)) {
            // Remove SAML inbound data.
            if (log.isDebugEnabled()) {
                log.debug("SAML inbound with issuer: " + storedSAMLIssuer + " has been removed from " +
                        "service provider with id: " + appId + ". Removing the stale SAML inbound data for " +
                        "issuer: " + storedSAMLIssuer);
            }
            try {
                SAMLSSOUtil.getSAMLSSOConfigService().removeServiceProvider(storedSAMLIssuer);
            } catch (IdentityException e) {
                String msg = "Error removing SAML inbound data for issuer: %s associated with " +
                        "service provider with id: %s during application update.";
                throw new IdentityApplicationManagementException(String.format(msg, storedSAMLIssuer, appId), e);
            }
        }
    }

    private boolean isSAMLInboundAssociationRemoved(String storeSAMLIssuer,
                                                    String updatedSAMLIssuer) {

        return storeSAMLIssuer != null && updatedSAMLIssuer == null;
    }

    private String getSAMLIssuer(ServiceProvider sp) {

        if (sp != null && sp.getInboundAuthenticationConfig() != null) {
            if (ArrayUtils.isNotEmpty(sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs())) {
                return Arrays.stream(sp.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs())
                        .filter(inbound -> StandardInboundProtocols.SAML2.equals(inbound.getInboundAuthType()))
                        .findAny()
                        .map(InboundAuthenticationRequestConfig::getInboundAuthKey)
                        .orElse(null);
            }
        }

        return null;
    }

    public void onPreCreateInbound(ServiceProvider serviceProvider, boolean isUpdate) throws
            IdentityApplicationManagementException {

        if (serviceProvider.getInboundAuthenticationConfig() != null &&
                serviceProvider.getInboundAuthenticationConfig().getInboundAuthenticationRequestConfigs() != null) {

            for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(authConfig.getInboundAuthType(), SAMLSSO)) {
                    String inboundConfiguration = authConfig.getInboundConfiguration();
                    if (inboundConfiguration != null) {
                        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO;
                        try {
                            samlssoServiceProviderDTO = unmarshelSAMLSSOServiceProviderDTO(
                                    authConfig.getInboundConfiguration(), serviceProvider.getApplicationName(),
                                    serviceProvider.getOwner().getTenantDomain());
                        } catch (IdentityApplicationManagementException e) {
                            String errorMsg = String.format("SAML inbound configuration in the file is not valid " +
                                    "for the application %s", serviceProvider.getApplicationName());
                            log.error(errorMsg, e);
                            return;
                        }

                        List<Property> propertyList = new ArrayList<>();
                        addSAMLInboundProperties(propertyList, samlssoServiceProviderDTO, isUpdate);
                        Property[] properties = propertyList.toArray(new Property[0]);
                        authConfig.setProperties(properties);
                    }
                    return;
                }
            }
        }
    }

    public void doExportServiceProvider(ServiceProvider serviceProvider, Boolean exportSecrets)
            throws IdentityApplicationManagementException {

        try {
            if (serviceProvider.getInboundAuthenticationConfig() != null &&
                    serviceProvider.getInboundAuthenticationConfig()
                            .getInboundAuthenticationRequestConfigs() != null) {

                for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                        .getInboundAuthenticationRequestConfigs()) {
                    if (StringUtils.equals(authConfig.getInboundAuthType(), SAMLSSO)) {

                        SAMLSSOServiceProviderDTO samlSP = null;
                        if (authConfig.getProperties() != null) {
                            samlSP = getServiceProviderDTO(authConfig.getProperties(),
                                    serviceProvider.getOwner().getTenantDomain());
                        }
                        if (samlSP == null) {
                            throw new IdentityApplicationManagementException(String.format("There is no saml " +
                                    "configured with %s", authConfig.getInboundAuthKey()));
                        }
                        JAXBContext jaxbContext = JAXBContext.newInstance(SAMLSSOServiceProviderDTO.class);
                        Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
                        jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
                        StringWriter sw = new StringWriter();
                        jaxbMarshaller.marshal(samlSP, sw);
                        authConfig.setInboundConfiguration(sw.toString());
                        authConfig.setProperties(new Property[0]);
                        return;
                    }
                }
            }
        } catch (JAXBException e) {
            throw new IdentityApplicationManagementException(String.format("Error in exporting SAML application " +
                    "%s@%s", serviceProvider.getApplicationName(), serviceProvider.getOwner().getTenantDomain()), e);
        }
    }

    private Registry getConfigSystemRegistry() {

        return (Registry) PrivilegedCarbonContext.getThreadLocalCarbonContext().getRegistry(RegistryType
                .SYSTEM_CONFIGURATION);
    }

    /**
     * Validate inbound auth SAML configurations.
     *
     * @param authConfig      saml auth config
     * @param applicationName application name
     * @param tenantDomain    tenant domain
     * @param isUpdate        whether the application update or create
     * @throws IdentityApplicationManagementValidationException throws if the config is not valid or already key exists.
     */
    private void validateSAMLSP(InboundAuthenticationRequestConfig authConfig, String applicationName, String
            tenantDomain, boolean isUpdate) throws IdentityApplicationManagementValidationException {

        List<String> validationMsg = new ArrayList<>();
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO;
        try {
            samlssoServiceProviderDTO = unmarshelSAMLSSOServiceProviderDTO(authConfig.getInboundConfiguration(),
                    applicationName, tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            String errorMsg = String.format("SAML inbound configuration in the file is not valid for the " +
                    "application %s", applicationName);
            log.error(errorMsg, e);
            validationMsg.add(errorMsg);
            return;
        }
        String issuer = samlssoServiceProviderDTO.getIssuer();
        if (StringUtils.isNotBlank(samlssoServiceProviderDTO.getIssuerQualifier())) {
            issuer = SAMLSSOUtil.getIssuerWithQualifier(issuer, samlssoServiceProviderDTO.getIssuerQualifier());
        }
        if (!authConfig.getInboundAuthKey().equals(issuer)) {
            validationMsg.add(String.format("The Inbound Auth Key of the  application name %s " +
                    "is not match with SAML issuer %s.", authConfig.getInboundAuthKey(), issuer));
        }
        SAMLSSOConfigService configAdmin = new SAMLSSOConfigService();

        if (!isUpdate) {
            try {
                SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTOs = configAdmin.getServiceProviders();
                if (serviceProviderInfoDTOs != null) {
                    for (SAMLSSOServiceProviderDTO sp : serviceProviderInfoDTOs.getServiceProviders()) {
                        if (sp.getIssuer().equals(authConfig.getInboundAuthKey())) {
                            validationMsg.add(String.format("Already a SAML configuration available with %s",
                                    authConfig.getInboundAuthKey()));
                            break;
                        }
                    }
                }
            } catch (IdentityException e) {
                // Do nothing, the issuer does exists.
            }
        }
        if (!validationMsg.isEmpty()) {
            throw new IdentityApplicationManagementValidationException(validationMsg.toArray(new String[0]));
        }
    }

    /**
     * Unmarshel SAMLSSOServiceProvider DTO
     *
     * @param authConfig          authentication config
     * @param serviceProviderName service provider name
     * @param tenantDomain        tenant domain
     * @return
     * @throws IdentityApplicationManagementException Identity Application Management Exception
     */
    private SAMLSSOServiceProviderDTO unmarshelSAMLSSOServiceProviderDTO(String authConfig, String
            serviceProviderName, String tenantDomain) throws
            IdentityApplicationManagementException {

        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(SAMLSSOServiceProviderDTO.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            return (SAMLSSOServiceProviderDTO) unmarshaller.unmarshal(new ByteArrayInputStream(
                    authConfig.getBytes(StandardCharsets.UTF_8)));
        } catch (JAXBException e) {
            throw new IdentityApplicationManagementException(String.format("Error in unmarshelling SAML application " +
                    "%s@%s", serviceProviderName, tenantDomain), e);
        }
    }

    private static void addSAMLInboundProperties(List<Property> propertyList,
                                                 SAMLSSOServiceProviderDTO serviceProviderDTO, boolean isUpdate) {
        addKeyValuePair(ISSUER, serviceProviderDTO.getIssuer(), propertyList);
        addKeyValuePair(ISSUER_QUALIFIER, serviceProviderDTO.getIssuerQualifier(), propertyList);
        for (String url : serviceProviderDTO.getAssertionConsumerUrls()) {
            addKeyValuePair(ASSERTION_CONSUMER_URLS, url, propertyList);
        }
        addKeyValuePair(DEFAULT_ASSERTION_CONSUMER_URL,
                serviceProviderDTO.getDefaultAssertionConsumerUrl(), propertyList);
        addKeyValuePair(SIGNING_ALGORITHM_URI, serviceProviderDTO.getSigningAlgorithmURI(), propertyList);
        addKeyValuePair(DIGEST_ALGORITHM_URI, serviceProviderDTO.getDigestAlgorithmURI(), propertyList);
        addKeyValuePair(ASSERTION_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDTO.getAssertionEncryptionAlgorithmURI(), propertyList);
        addKeyValuePair(KEY_ENCRYPTION_ALGORITHM_URI,
                serviceProviderDTO.getKeyEncryptionAlgorithmURI(), propertyList);
        addKeyValuePair(CERT_ALIAS, serviceProviderDTO.getCertAlias(), propertyList);
        addKeyValuePair(ATTRIBUTE_CONSUMING_SERVICE_INDEX, serviceProviderDTO.getAttributeConsumingServiceIndex(),
                propertyList);
        addKeyValuePair(DO_SIGN_RESPONSE, serviceProviderDTO.isDoSignResponse() ? "true" : "false", propertyList);
        addKeyValuePair(DO_SINGLE_LOGOUT, serviceProviderDTO.isDoSingleLogout() ? "true" : "false", propertyList);
        addKeyValuePair(DO_FRONT_CHANNEL_LOGOUT,
                serviceProviderDTO.isDoFrontChannelLogout() ? "true" : "false", propertyList);
        addKeyValuePair(FRONT_CHANNEL_LOGOUT_BINDING,
                serviceProviderDTO.getFrontChannelLogoutBinding(), propertyList);
        addKeyValuePair(IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                serviceProviderDTO.isAssertionQueryRequestProfileEnabled() ? "true" : "false", propertyList);
        addKeyValuePair(SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                serviceProviderDTO.getSupportedAssertionQueryRequestTypes(), propertyList);
        addKeyValuePair(ENABLE_SAML2_ARTIFACT_BINDING,
                serviceProviderDTO.isEnableSAML2ArtifactBinding() ? "true" : "false", propertyList);
        addKeyValuePair(DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                serviceProviderDTO.isDoValidateSignatureInArtifactResolve() ? "true" : "false", propertyList);
        addKeyValuePair(LOGIN_PAGE_URL, serviceProviderDTO.getLoginPageURL(), propertyList);
        addKeyValuePair(SLO_RESPONSE_URL, serviceProviderDTO.getSloResponseURL(), propertyList);
        addKeyValuePair(SLO_REQUEST_URL, serviceProviderDTO.getSloRequestURL(), propertyList);
        for (String claim : serviceProviderDTO.getRequestedClaims()) {
            addKeyValuePair(REQUESTED_CLAIMS, claim, propertyList);
        }
        for (String audience : serviceProviderDTO.getRequestedAudiences()) {
            addKeyValuePair(REQUESTED_AUDIENCES, audience, propertyList);
        }
        for (String recipient : serviceProviderDTO.getRequestedRecipients()) {
            addKeyValuePair(REQUESTED_RECIPIENTS, recipient, propertyList);
        }
        addKeyValuePair(ENABLE_ATTRIBUTES_BY_DEFAULT,
                serviceProviderDTO.isEnableAttributesByDefault() ? "true" : "false", propertyList);
        addKeyValuePair(NAME_ID_CLAIM_URI, serviceProviderDTO.getNameIdClaimUri(), propertyList);
        addKeyValuePair(NAME_ID_FORMAT, serviceProviderDTO.getNameIDFormat(), propertyList);
        addKeyValuePair(IDP_INIT_SSO_ENABLED,
                serviceProviderDTO.isIdPInitSSOEnabled() ? "true" : "false", propertyList);
        addKeyValuePair(IDP_INIT_SLO_ENABLED,
                serviceProviderDTO.isIdPInitSLOEnabled() ? "true" : "false", propertyList);
        for (String url : serviceProviderDTO.getIdpInitSLOReturnToURLs()) {
            addKeyValuePair(IDP_INIT_SLO_RETURN_TO_URLS, url, propertyList);
        }
        addKeyValuePair(DO_ENABLE_ENCRYPTED_ASSERTION,
                serviceProviderDTO.isDoEnableEncryptedAssertion() ? "true" : "false", propertyList);
        addKeyValuePair(DO_VALIDATE_SIGNATURE_IN_REQUESTS,
                serviceProviderDTO.isDoValidateSignatureInRequests() ? "true" : "false", propertyList);
        addKeyValuePair(IDP_ENTITY_ID_ALIAS, serviceProviderDTO.getIdpEntityIDAlias(), propertyList);
        addKeyValuePair(IS_UPDATE, isUpdate ? "true" : "false", propertyList);
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

    private static SAMLSSOServiceProviderDTO getServiceProviderDTO(Property[] properties, String tenantDomain) {
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));

        SAMLSSOServiceProviderDTO serviceProviderDTO = new SAMLSSOServiceProviderDTO();
        if (map.containsKey(ISSUER)) {
            serviceProviderDTO.setIssuer(map.get(ISSUER).get(0));
        } else {
            if (log.isDebugEnabled()) {
                log.debug("SAML SP not found for issuer: " + ISSUER + " in tenantDomain: " + tenantDomain);
            }
            return null;
        }
        serviceProviderDTO.setIssuerQualifier(getSingleValue(map, ISSUER_QUALIFIER));
        serviceProviderDTO.setAssertionConsumerUrls(getMultiValues(map, ASSERTION_CONSUMER_URLS));

        serviceProviderDTO.setDefaultAssertionConsumerUrl(getSingleValue(map, DEFAULT_ASSERTION_CONSUMER_URL));
        serviceProviderDTO.setSigningAlgorithmURI(getSingleValue(map, SIGNING_ALGORITHM_URI));
        serviceProviderDTO.setDigestAlgorithmURI(getSingleValue(map, DIGEST_ALGORITHM_URI));
        serviceProviderDTO.setAssertionEncryptionAlgorithmURI(getSingleValue(map, ASSERTION_ENCRYPTION_ALGORITHM_URI));
        serviceProviderDTO.setKeyEncryptionAlgorithmURI(getSingleValue(map, KEY_ENCRYPTION_ALGORITHM_URI));
        serviceProviderDTO.setCertAlias(getSingleValue(map, CERT_ALIAS));
        serviceProviderDTO.setAttributeConsumingServiceIndex(getSingleValue(map, ATTRIBUTE_CONSUMING_SERVICE_INDEX));

        if (map.containsKey(ATTRIBUTE_CONSUMING_SERVICE_INDEX)
                && StringUtils.isNotBlank(map.get(ATTRIBUTE_CONSUMING_SERVICE_INDEX).get(0))) {
            serviceProviderDTO.setEnableAttributeProfile(true);
        }

        serviceProviderDTO.setDoSignResponse(Boolean.parseBoolean(getSingleValue(map, DO_SIGN_RESPONSE)));
                /*
                According to the spec, "The <Assertion> element(s) in the <Response> MUST be signed". Therefore we
                should not reply on any property to decide this behaviour. Hence the property is set to sign by default.
                */
        serviceProviderDTO.setDoSignAssertions(true);
        serviceProviderDTO.setDoSingleLogout(Boolean.parseBoolean(getSingleValue(map, DO_SINGLE_LOGOUT)));
        serviceProviderDTO.setDoFrontChannelLogout(Boolean.parseBoolean(getSingleValue(map, DO_FRONT_CHANNEL_LOGOUT)));
        serviceProviderDTO.setFrontChannelLogoutBinding(getSingleValue(map, FRONT_CHANNEL_LOGOUT_BINDING));
        serviceProviderDTO.setAssertionQueryRequestProfileEnabled(Boolean.parseBoolean(
                getSingleValue(map, IS_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED)));
        serviceProviderDTO.setSupportedAssertionQueryRequestTypes(
                getSingleValue(map, SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES));
        serviceProviderDTO.setEnableSAML2ArtifactBinding(Boolean.parseBoolean(
                getSingleValue(map, ENABLE_SAML2_ARTIFACT_BINDING)));
        serviceProviderDTO.setDoValidateSignatureInArtifactResolve(
                Boolean.parseBoolean(getSingleValue(map, DO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE)));

        if (!map.containsKey(LOGIN_PAGE_URL) || map.get(LOGIN_PAGE_URL).get(0) == null
                || "null".equals(map.get(LOGIN_PAGE_URL).get(0))) {
            serviceProviderDTO.setLoginPageURL("");
        } else {
            serviceProviderDTO.setLoginPageURL(getSingleValue(map, LOGIN_PAGE_URL));
        }

        serviceProviderDTO.setSloResponseURL(getSingleValue(map, SLO_RESPONSE_URL));
        serviceProviderDTO.setSloRequestURL(getSingleValue(map, SLO_REQUEST_URL));
        serviceProviderDTO.setRequestedClaims(getMultiValues(map, REQUESTED_CLAIMS));
        serviceProviderDTO.setRequestedAudiences(getMultiValues(map, REQUESTED_AUDIENCES));
        serviceProviderDTO.setRequestedRecipients(getMultiValues(map, REQUESTED_RECIPIENTS));
        serviceProviderDTO.setEnableAttributesByDefault(Boolean.parseBoolean(
                getSingleValue(map, ENABLE_ATTRIBUTES_BY_DEFAULT)));
        serviceProviderDTO.setNameIdClaimUri(getSingleValue(map, NAME_ID_CLAIM_URI));
        serviceProviderDTO.setNameIDFormat(getSingleValue(map, NAME_ID_FORMAT));

        if (serviceProviderDTO.getNameIDFormat() == null) {
            serviceProviderDTO.setNameIDFormat(NameIdentifier.UNSPECIFIED);
        }
        serviceProviderDTO.setNameIDFormat(serviceProviderDTO.getNameIDFormat().replace(":", "/"));

        serviceProviderDTO.setIdPInitSSOEnabled(Boolean.parseBoolean(getSingleValue(map, IDP_INIT_SSO_ENABLED)));
        serviceProviderDTO.setIdPInitSLOEnabled(Boolean.parseBoolean(getSingleValue(map, IDP_INIT_SLO_ENABLED)));
        serviceProviderDTO.setIdpInitSLOReturnToURLs(getMultiValues(map, IDP_INIT_SLO_RETURN_TO_URLS));
        serviceProviderDTO.setDoEnableEncryptedAssertion(Boolean.parseBoolean(
                getSingleValue(map, DO_ENABLE_ENCRYPTED_ASSERTION)));
        serviceProviderDTO.setDoValidateSignatureInRequests(Boolean.parseBoolean(
                getSingleValue(map, DO_VALIDATE_SIGNATURE_IN_REQUESTS)));
        serviceProviderDTO.setIdpEntityIDAlias(getSingleValue(map, IDP_ENTITY_ID_ALIAS));
        return serviceProviderDTO;
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
}
