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

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.IdentityRegistryResources;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;

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
    private static final String IS_UPDATE = "isUpdate";

    @Override
    public int getDefaultOrderId() {
        // Since we are deleting SAML data in pre delete operation, we want this listener to be executed as
        // late as possible allowing other listeners to execute and break the flow if required.
        return 900;
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
                        SAMLSSOServiceProviderDTO serviceProviderDTO;
                        try {
                            serviceProviderDTO = unmarshelSAMLSSOServiceProviderDTO(
                                    authConfig.getInboundConfiguration(), serviceProvider.getApplicationName(),
                                    serviceProvider.getOwner().getTenantDomain());
                        } catch (IdentityApplicationManagementException e) {
                            String errorMsg = String.format("SAML inbound configuration in the file is not valid " +
                                    "for the application %s", serviceProvider.getApplicationName());
                            log.error(errorMsg, e);
                            return;
                        }

                        List<Property> propertyList = new ArrayList<>();

                        if (serviceProviderDTO.getNameIDFormat() == null) {
                            serviceProviderDTO.setNameIDFormat(NameIdentifier.UNSPECIFIED);
                        } else {
                            serviceProviderDTO.setNameIDFormat(serviceProviderDTO.getNameIDFormat().replace("/", ":"));
                        }
                        if (serviceProviderDTO.isEnableAttributeProfile()) {
                            String attributeConsumingIndex = serviceProviderDTO.getAttributeConsumingServiceIndex();
                            if (StringUtils.isEmpty(attributeConsumingIndex)) {
                                try {
                                    serviceProviderDTO.setAttributeConsumingServiceIndex(
                                            Integer.toString(IdentityUtil.getRandomInteger()));
                                } catch (IdentityException e) {
                                    throw new IdentityApplicationManagementException("Error happened when generating " +
                                            "a Random Integer", e);
                                }
                            }
                        } else {
                            serviceProviderDTO.setAttributeConsumingServiceIndex("");
                            if (serviceProviderDTO.isEnableAttributesByDefault()) {
                                log.warn("Enable Attribute Profile must be selected to activate it by default. " +
                                        "EnableAttributesByDefault will be disabled.");
                            }
                            serviceProviderDTO.setEnableAttributesByDefault(false);
                        }

                        addSAMLInboundProperties(propertyList, serviceProviderDTO, isUpdate);
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
                            samlSP = getServiceProviderDTO(authConfig.getProperties());
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
                        //Have to clear the the create properties to make the import xml equal to the exported xml
                        //can't just clear properties because properties may have added elsewhere.
                        //TODO : find a better property clear solution
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

    /**
     * Unmarshel SAMLSSOServiceProvider DTO.
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
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ISSUER, serviceProviderDTO.getIssuer(), propertyList);
        for (String url : serviceProviderDTO.getAssertionConsumerUrls()) {
            addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_CONS_URLS, url, propertyList);
        }
        addKeyValuePair(IdentityRegistryResources.PROP_DEFAULT_SAML_SSO_ASSERTION_CONS_URL,
                serviceProviderDTO.getDefaultAssertionConsumerUrl(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_CERT_ALIAS,
                serviceProviderDTO.getCertAlias(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_LOGIN_PAGE_URL,
                serviceProviderDTO.getLoginPageURL(), propertyList);
        addKeyValuePair(
                IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT,
                serviceProviderDTO.getNameIDFormat(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_SIGNING_ALGORITHM, serviceProviderDTO
                .getSigningAlgorithmURI(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_DIGEST_ALGORITHM, serviceProviderDTO
                .getDigestAlgorithmURI(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM, serviceProviderDTO
                .getAssertionEncryptionAlgorithmURI(), propertyList);
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM, serviceProviderDTO
                .getKeyEncryptionAlgorithmURI(), propertyList);
        if (serviceProviderDTO.getNameIdClaimUri() != null
                && serviceProviderDTO.getNameIdClaimUri().trim().length() > 0) {
            addKeyValuePair(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI, "true", propertyList);
            addKeyValuePair(
                    IdentityRegistryResources.PROP_SAML_SSO_NAMEID_CLAIMURI, serviceProviderDTO.getNameIdClaimUri(),
                    propertyList);
        } else {
            addKeyValuePair(
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI, "false", propertyList);
        }

        String doSingleLogout = String.valueOf(serviceProviderDTO.isDoSingleLogout());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT, doSingleLogout, propertyList);
        if (serviceProviderDTO.isDoSingleLogout()) {
            if (StringUtils.isNotBlank(serviceProviderDTO.getSloResponseURL())) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SLO_RESPONSE_URL,
                        serviceProviderDTO.getSloResponseURL(), propertyList);
            }
            if (StringUtils.isNotBlank(serviceProviderDTO.getSloRequestURL())) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SLO_REQUEST_URL,
                        serviceProviderDTO.getSloRequestURL(), propertyList);
            }
            // Create doFrontChannelLogout property in the registry.
            String doFrontChannelLogout = String.valueOf(serviceProviderDTO.isDoFrontChannelLogout());
            addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT, doFrontChannelLogout,
                    propertyList);
            if (serviceProviderDTO.isDoFrontChannelLogout()) {
                // Create frontChannelLogoutMethod property in the registry.
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING,
                        serviceProviderDTO.getFrontChannelLogoutBinding(), propertyList);
            }
        }

        String doSignResponse = String.valueOf(serviceProviderDTO.isDoSignResponse());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE, doSignResponse, propertyList);
        String isAssertionQueryRequestProfileEnabled = String.valueOf(serviceProviderDTO
                .isAssertionQueryRequestProfileEnabled());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED,
                isAssertionQueryRequestProfileEnabled, propertyList);
        String supportedAssertionQueryRequestTypes = serviceProviderDTO.getSupportedAssertionQueryRequestTypes();
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES,
                supportedAssertionQueryRequestTypes, propertyList);
        String isEnableSAML2ArtifactBinding = String.valueOf(serviceProviderDTO.isEnableSAML2ArtifactBinding());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING,
                isEnableSAML2ArtifactBinding, propertyList);

        String doSignAssertions = String.valueOf(serviceProviderDTO.isDoSignAssertions());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS, doSignAssertions, propertyList);

        String isSamlECP = String.valueOf(serviceProviderDTO.isSamlECP());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_ENABLE_ECP, isSamlECP, propertyList);
        if (CollectionUtils.isNotEmpty(Arrays.asList(serviceProviderDTO.getRequestedClaims()))) {
            for (String requestedClaim : serviceProviderDTO.getRequestedClaims()) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS, requestedClaim, propertyList);
            }
        }

        addKeyValuePair(ATTRIBUTE_CONSUMING_SERVICE_INDEX, serviceProviderDTO.getAttributeConsumingServiceIndex(),
                propertyList);

        if (CollectionUtils.isNotEmpty(Arrays.asList(serviceProviderDTO.getRequestedAudiences()))) {
            for (String requestedAudience : serviceProviderDTO.getRequestedAudiences()) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES, requestedAudience,
                        propertyList);
            }
        }
        if (CollectionUtils.isNotEmpty(Arrays.asList(serviceProviderDTO.getRequestedRecipients()))) {
            for (String requestedRecipient : serviceProviderDTO.getRequestedRecipients()) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS, requestedRecipient,
                        propertyList);
            }
        }

        String enableAttributesByDefault = String.valueOf(serviceProviderDTO.isEnableAttributesByDefault());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT,
                enableAttributesByDefault, propertyList);

        String idPInitSSOEnabled = String.valueOf(serviceProviderDTO.isIdPInitSSOEnabled());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED, idPInitSSOEnabled, propertyList);

        String idPInitSLOEnabled = String.valueOf(serviceProviderDTO.isIdPInitSLOEnabled());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED, idPInitSLOEnabled, propertyList);

        if (serviceProviderDTO.isIdPInitSLOEnabled() && serviceProviderDTO.getIdpInitSLOReturnToURLs().length > 0) {
            for (String sloReturnUrl : serviceProviderDTO.getIdpInitSLOReturnToURLs()) {
                addKeyValuePair(IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS, sloReturnUrl,
                        propertyList);
            }
        }
        String enableEncryptedAssertion = String.valueOf(serviceProviderDTO.isDoEnableEncryptedAssertion());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION, enableEncryptedAssertion,
                propertyList);

        String validateSignatureInRequests = String.valueOf(serviceProviderDTO.isDoValidateSignatureInRequests());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS,
                validateSignatureInRequests, propertyList);

        String validateSignatureInArtifactResolve =
                String.valueOf(serviceProviderDTO.isDoValidateSignatureInArtifactResolve());
        addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE,
                validateSignatureInArtifactResolve, propertyList);
        if (StringUtils.isNotBlank(serviceProviderDTO.getIssuerQualifier())) {
            addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER, serviceProviderDTO
                    .getIssuerQualifier(), propertyList);
        }
        if (StringUtils.isNotBlank(serviceProviderDTO.getIdpEntityIDAlias())) {
            addKeyValuePair(IdentityRegistryResources.PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS, serviceProviderDTO
                    .getIdpEntityIDAlias(), propertyList);
        }
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

    private static SAMLSSOServiceProviderDTO getServiceProviderDTO(Property[] properties) {
        HashMap<String, List<String>> map = new HashMap<>(Arrays.stream(properties).collect(Collectors.groupingBy(
                Property::getName, Collectors.mapping(Property::getValue, Collectors.toList()))));

        SAMLSSOServiceProviderDTO serviceProviderDTO = new SAMLSSOServiceProviderDTO();
        serviceProviderDTO.setIssuer(getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ISSUER));

        serviceProviderDTO.setAssertionConsumerUrls(getMultiValues(map,
                IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_CONS_URLS));
        serviceProviderDTO.setDefaultAssertionConsumerUrl(getSingleValue(map,
                IdentityRegistryResources.PROP_DEFAULT_SAML_SSO_ASSERTION_CONS_URL));
        serviceProviderDTO.setCertAlias(getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ISSUER_CERT_ALIAS));

        if (StringUtils.isNotEmpty(getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_SIGNING_ALGORITHM))) {
            serviceProviderDTO.setSigningAlgorithmURI(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SSO_SIGNING_ALGORITHM));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED) !=
                null) {
            serviceProviderDTO.setAssertionQueryRequestProfileEnabled(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ASSERTION_QUERY_REQUEST_PROFILE_ENABLED).trim()));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES) !=
                null) {
            serviceProviderDTO.setSupportedAssertionQueryRequestTypes(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES).trim());
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING) !=
                null) {
            serviceProviderDTO.setEnableSAML2ArtifactBinding(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_SAML2_ARTIFACT_BINDING).trim()));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_DIGEST_ALGORITHM))) {
            serviceProviderDTO.setDigestAlgorithmURI(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SSO_DIGEST_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, IdentityRegistryResources
                .PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM))) {
            serviceProviderDTO.setAssertionEncryptionAlgorithmURI(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM));
        }

        if (StringUtils.isNotEmpty(getSingleValue(map, IdentityRegistryResources
                .PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM))) {
            serviceProviderDTO.setKeyEncryptionAlgorithmURI(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SSO_KEY_ENCRYPTION_ALGORITHM));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT) != null) {
            serviceProviderDTO.setDoSingleLogout(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SINGLE_LOGOUT).trim()));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT) != null) {
            serviceProviderDTO.setNameIDFormat(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_NAMEID_FORMAT));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI) != null) {
            if (Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_NAMEID_CLAIMURI).trim())) {
                serviceProviderDTO.setNameIdClaimUri(getSingleValue(map,
                        IdentityRegistryResources.PROP_SAML_SSO_NAMEID_CLAIMURI));
            }
        }

        serviceProviderDTO.setLoginPageURL(getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_LOGIN_PAGE_URL));

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE) != null) {
            serviceProviderDTO.setDoSignResponse(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_RESPONSE).trim()));
        }

        if (serviceProviderDTO.isDoSingleLogout()) {
            serviceProviderDTO.setSloResponseURL(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SLO_RESPONSE_URL));
            serviceProviderDTO.setSloRequestURL(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SLO_REQUEST_URL));
            // Check front channel logout enable.
            if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT) != null) {
                serviceProviderDTO.setDoFrontChannelLogout(Boolean.parseBoolean(getSingleValue(map,
                        IdentityRegistryResources.PROP_SAML_SSO_DO_FRONT_CHANNEL_LOGOUT).trim()));
                if (serviceProviderDTO.isDoFrontChannelLogout()) {
                    if (getSingleValue(map, IdentityRegistryResources.
                            PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING) != null) {
                        serviceProviderDTO.setFrontChannelLogoutBinding(getSingleValue(map,
                                IdentityRegistryResources.PROP_SAML_SSO_FRONT_CHANNEL_LOGOUT_BINDING));
                    } else {
                        // Default is redirect-binding.
                        serviceProviderDTO.setFrontChannelLogoutBinding(IdentityRegistryResources
                                .DEFAULT_FRONT_CHANNEL_LOGOUT_BINDING);
                    }

                }
            }
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS) != null) {
            serviceProviderDTO.setDoSignAssertions(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_DO_SIGN_ASSERTIONS).trim()));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_ENABLE_ECP) != null) {
            serviceProviderDTO.setSamlECP(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_ENABLE_ECP).trim()));
        }

        if (getSingleValue(map, ATTRIBUTE_CONSUMING_SERVICE_INDEX) != null) {
            serviceProviderDTO.setAttributeConsumingServiceIndex(getSingleValue(map,
                    ATTRIBUTE_CONSUMING_SERVICE_INDEX));
        } else {
            // Specific DB's (like oracle) returns empty strings as null.
            serviceProviderDTO.setAttributeConsumingServiceIndex("");
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS) != null) {
            serviceProviderDTO.setRequestedClaims(getMultiValues(map,
                    IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_CLAIMS));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES) != null) {
            serviceProviderDTO.setRequestedAudiences(getMultiValues(map,
                    IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_AUDIENCES));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS) != null) {
            serviceProviderDTO.setRequestedRecipients(getMultiValues(map,
                    IdentityRegistryResources.PROP_SAML_SSO_REQUESTED_RECIPIENTS));
        }

        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT) != null) {
            String enableAttrByDefault = getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ATTRIBUTES_BY_DEFAULT);
            serviceProviderDTO.setEnableAttributesByDefault(Boolean.parseBoolean(enableAttrByDefault));
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED) != null) {
            serviceProviderDTO.setIdPInitSSOEnabled(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_IDP_INIT_SSO_ENABLED).trim()));
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED) != null) {
            serviceProviderDTO.setIdPInitSLOEnabled(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SLO_IDP_INIT_SLO_ENABLED).trim()));
            if (serviceProviderDTO.isIdPInitSLOEnabled() && getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS) != null) {
                serviceProviderDTO.setIdpInitSLOReturnToURLs(getMultiValues(map,
                        IdentityRegistryResources.PROP_SAML_IDP_INIT_SLO_RETURN_URLS));
            }
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION) != null) {
            serviceProviderDTO.setDoEnableEncryptedAssertion(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ENABLE_ENCRYPTED_ASSERTION).trim()));
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS) != null) {
            serviceProviderDTO.setDoValidateSignatureInRequests(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_REQUESTS).trim()));
        }
        if (getSingleValue(map,
                IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE) != null) {
            serviceProviderDTO.setDoValidateSignatureInArtifactResolve(Boolean.parseBoolean(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_VALIDATE_SIGNATURE_IN_ARTIFACT_RESOLVE).trim()));
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER) != null) {
            serviceProviderDTO.setIssuerQualifier(getSingleValue(map,
                    IdentityRegistryResources.PROP_SAML_SSO_ISSUER_QUALIFIER));
        }
        if (getSingleValue(map, IdentityRegistryResources.PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS) != null) {
            serviceProviderDTO.setIdpEntityIDAlias(getSingleValue(map, IdentityRegistryResources
                    .PROP_SAML_SSO_IDP_ENTITY_ID_ALIAS));
        }
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
