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

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.context.RegistryType;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementValidationException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConfigService;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderInfoDTO;
import org.wso2.carbon.registry.core.Registry;

import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

/**
 * Application listener responsible for SAML inbound configurations.
 */
public class SAMLApplicationMgtListener extends AbstractApplicationMgtListener {

    private static Log log = LogFactory.getLog(SAMLApplicationMgtListener.class);
    public static final String SAMLSSO = "samlsso";

    @Override
    public int getDefaultOrderId() {

        return 15;
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
                        validateSAMLSP(authConfig, serviceProvider.getApplicationName(),
                                serviceProvider.getOwner().getTenantDomain(), isUpdate);
                    }
                    return;
                }
            }
        }
    }

    public void doImportServiceProvider(ServiceProvider serviceProvider) throws IdentityApplicationManagementException {

        try {
            if (serviceProvider.getInboundAuthenticationConfig() != null &&
                    serviceProvider.getInboundAuthenticationConfig()
                            .getInboundAuthenticationRequestConfigs() != null) {

                for (InboundAuthenticationRequestConfig authConfig : serviceProvider.getInboundAuthenticationConfig()
                        .getInboundAuthenticationRequestConfigs()) {
                    if (StringUtils.equals(authConfig.getInboundAuthType(), SAMLSSO)) {

                        String inboundConfiguration = authConfig.getInboundConfiguration();
                        if (StringUtils.isEmpty(inboundConfiguration)) {
                            String errorMsg = String.format("No inbound configurations found for oauth in the" +
                                            " imported %s", serviceProvider.getApplicationName());
                            throw new IdentityApplicationManagementException(errorMsg);
                        }
                        String inboundAuthKey = authConfig.getInboundAuthKey();
                        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = unmarshelSAMLSSOServiceProviderDTO(
                                inboundConfiguration, serviceProvider.getApplicationName(),
                                serviceProvider.getOwner().getTenantDomain());

                        SAMLSSOConfigService configAdmin = new SAMLSSOConfigService();

                        try {
                            SAMLSSOServiceProviderDTO savedSamlSP = null;
                            SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTOs = configAdmin.getServiceProviders();
                            if (serviceProviderInfoDTOs != null) {
                                for (SAMLSSOServiceProviderDTO sp : serviceProviderInfoDTOs.getServiceProviders()) {
                                    if (sp.getIssuer().equals(inboundAuthKey)) {
                                        savedSamlSP = sp;
                                        break;
                                    }
                                }
                            }
                            if (savedSamlSP != null) {
                                configAdmin.removeServiceProvider(samlssoServiceProviderDTO.getIssuer());
                            }
                        } catch (IdentityException e) {
                            // Do nothing, the issuer does exists.
                        }
                        configAdmin.addRPServiceProvider(samlssoServiceProviderDTO);
                        return;
                    }
                }
            }
        } catch (IdentityException e) {
            throw new IdentityApplicationManagementException("Error occurred when importing SAML application ", e);
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
                        SAMLSSOConfigService configAdmin = new SAMLSSOConfigService();
                        SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTOs = configAdmin.getServiceProviders();
                        if (serviceProviderInfoDTOs != null) {
                            for (SAMLSSOServiceProviderDTO sp : serviceProviderInfoDTOs.getServiceProviders()) {
                                if (sp.getIssuer().equals(authConfig.getInboundAuthKey())) {
                                    samlSP = sp;
                                    break;
                                }
                            }
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
                        return;
                    }
                }
            }
        } catch (IdentityException e) {
            throw new IdentityApplicationManagementException("Error occurred when retrieving SAML application ", e);
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
        if (!authConfig.getInboundAuthKey().equals(samlssoServiceProviderDTO.getIssuer())) {
            validationMsg.add(String.format("The Inbound Auth Key of the  application name %s " +
                            "is not match with SAML issuer %s.", authConfig.getInboundAuthKey(),
                    samlssoServiceProviderDTO.getIssuer()));
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
}
