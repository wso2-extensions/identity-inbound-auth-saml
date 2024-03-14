/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementClientException;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolConfigurationDTO;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.application.mgt.inbound.protocol.ApplicationInboundAuthConfigHandler;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ProtocolConfigDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.StandardInboundProtocols.SAML2;
import static org.wso2.carbon.identity.application.mgt.inbound.InboundFunctions.getInboundAuthKey;

/**
 * SAML2 inbound authentication configuration handler.
 */
public class SAML2InboundAuthConfigHandler implements ApplicationInboundAuthConfigHandler {
    
    private static final String ATTRIBUTE_CONSUMING_SERVICE_INDEX = "attrConsumServiceIndex";
    
    /**
     * Checks whether this handler can handle the inbound authentication request.
     *
     * @param inboundProtocolsDTO Inbound protocols DTO.
     * @return True if InboundProtocolDTO contains SAML inbound auth configs.
     */
    @Override
    public boolean canHandle(InboundProtocolsDTO inboundProtocolsDTO) {
        
        return inboundProtocolsDTO.getInboundProtocolConfigurationMap().containsKey(SAML2);
    }
    
    /**
     * Checks whether this handler can handle the inbound authentication request.
     *
     * @param protocolName Name of the protocol.
     * @return True if the protocolName is "samlsso".
     */
    @Override
    public boolean canHandle(String protocolName) {
        
        return StringUtils.containsIgnoreCase(ApplicationConstants.StandardInboundProtocols.SAML2, protocolName);
    }
    
    /**
     * Creates the inbound authentication request config from InboundProtocolConfigurationDTO.
     *
     * @param serviceProvider     Service provider.
     * @param inboundProtocolsDTO Inbound protocols DTO.
     * @return InboundAuthenticationRequestConfig.
     * @throws IdentityApplicationManagementException If an error occurs while creating the config.
     */
    @Override
    public InboundAuthenticationRequestConfig handleConfigCreation(ServiceProvider serviceProvider,
                                                                   InboundProtocolsDTO inboundProtocolsDTO)
            throws IdentityApplicationManagementException {
        
        SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = getSAML2ProtocolConfigDTO(inboundProtocolsDTO);
        try {
            return createSAMLInbound(serviceProvider, saml2ProtocolConfigDTO);
        } catch (IdentitySAML2ClientException e) {
            throw new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentitySAML2SSOException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * Updates the inbound authentication request config from InboundProtocolConfigurationDTO.
     *
     * @param serviceProvider                 Service provider.
     * @param inboundProtocolConfigurationDTO Inbound protocol configuration DTO.
     * @return InboundAuthenticationRequestConfig.
     * @throws IdentityApplicationManagementException If an error occurs while updating the config.
     */
    @Override
    public InboundAuthenticationRequestConfig handleConfigUpdate(
            ServiceProvider serviceProvider, InboundProtocolConfigurationDTO inboundProtocolConfigurationDTO)
            throws IdentityApplicationManagementException {
        
        SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = (SAML2ProtocolConfigDTO) inboundProtocolConfigurationDTO;
        try {
            return updateSAMLInbound(serviceProvider, saml2ProtocolConfigDTO);
        } catch (IdentitySAML2ClientException e) {
            throw new IdentityApplicationManagementClientException(e.getErrorCode(), e.getMessage(), e);
        } catch (IdentitySAML2SSOException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * Deletes the inbound authentication request config.
     *
     * @param issuer Issuer of the SAMl2 application.
     * @throws IdentityApplicationManagementException If an error occurs while deleting the config.
     */
    @Override
    public void handleConfigDeletion(String issuer) throws IdentityApplicationManagementException {
        
        try {
            IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService().removeServiceProvider(issuer,
                    false);
        } catch (IdentityException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    /**
     * Retrieves the inbound authentication request config.
     *
     * @param issuer Issuer of the SAMl2 application.
     * @return InboundProtocolConfigurationDTO.
     * @throws IdentityApplicationManagementException If an error occurs while retrieving the config.
     */
    @Override
    public InboundProtocolConfigurationDTO handleConfigRetrieval(String issuer)
            throws IdentityApplicationManagementException {
        
        try {
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
            SAMLSSOServiceProviderDTO samlSSOServiceProviderDTO = IdentitySAMLSSOServiceComponentHolder.getInstance()
                    .getSamlSSOConfigService().getServiceProvider(issuer);
            saml2ProtocolConfigDTO.setManualConfiguration(samlSSOServiceProviderDTO);
            return saml2ProtocolConfigDTO;
        } catch (IdentityException e) {
            throw new IdentityApplicationManagementException(e.getErrorCode(), e.getMessage(), e);
        }
    }
    
    private static SAML2ProtocolConfigDTO getSAML2ProtocolConfigDTO(InboundProtocolsDTO inboundProtocolsDTO) {
        
        InboundProtocolConfigurationDTO inboundProtocolConfigurationDTO = inboundProtocolsDTO
                .getInboundProtocolConfigurationMap().get(SAML2);
        return (SAML2ProtocolConfigDTO) inboundProtocolConfigurationDTO;
    }
    
    private InboundAuthenticationRequestConfig createSAMLInbound(ServiceProvider serviceProvider,
                                                         SAML2ProtocolConfigDTO saml2Configuration)
            throws IdentitySAML2SSOException {
        
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = getSamlSsoServiceProviderDTO(saml2Configuration);
        
        // Set certificate if available.
        if (samlssoServiceProviderDTO.getCertificateContent() != null) {
            serviceProvider.setCertificateContent(base64Encode(samlssoServiceProviderDTO.getCertificateContent()));
        }
        
        return createInboundAuthenticationRequestConfig(samlssoServiceProviderDTO);
    }
    
    private static SAMLSSOServiceProviderDTO getSamlSsoServiceProviderDTO(SAML2ProtocolConfigDTO saml2ProtocolConfigDTO)
            throws IdentitySAML2SSOException {
        
        SAMLSSOServiceProviderDTO samlManualConfiguration = saml2ProtocolConfigDTO.getManualConfiguration();
        
        if (saml2ProtocolConfigDTO.getMetadataFile() != null) {
            return createSAMLSpWithMetadataFile(saml2ProtocolConfigDTO.getMetadataFile());
        } else if (saml2ProtocolConfigDTO.getMetadataURL() != null) {
            return createSAMLSpWithMetadataUrl(saml2ProtocolConfigDTO.getMetadataURL());
        } else if (samlManualConfiguration != null) {
            return createSAMLSpWithManualConfiguration(samlManualConfiguration);
        } else {
            throw new IdentitySAML2ClientException("Invalid SAML2 Configuration. One of metadataFile, metaDataUrl or " +
                    "serviceProvider manual configuration needs to be present.");
        }
    }
    
    private static SAMLSSOServiceProviderDTO createSAMLSpWithMetadataFile(String encodedMetaFileContent)
            throws IdentitySAML2SSOException {
        
        byte[] metaData = Base64.getDecoder().decode(encodedMetaFileContent.getBytes(StandardCharsets.UTF_8));
        String base64DecodedMetadata = new String(metaData, StandardCharsets.UTF_8);
        
        return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService()
                .uploadRPServiceProvider(base64DecodedMetadata, false);
    }
    
    private static SAMLSSOServiceProviderDTO createSAMLSpWithMetadataUrl(String metadataUrl)
            throws IdentitySAML2SSOException {
        
        return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService()
                .createServiceProviderWithMetadataURL(metadataUrl, false);
    }
    
    private static SAMLSSOServiceProviderDTO createSAMLSpWithManualConfiguration(
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO) throws IdentitySAML2SSOException {
        
        try {
            return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService()
                    .createServiceProvider(samlssoServiceProviderDTO, false);
        } catch (IdentityException e) {
            throw handleException("Error while creating SAML2 service provider.", e);
        }
    }
    
    private static String base64Encode(String content) {
        
        return new String(Base64.getEncoder().encode(content.getBytes(StandardCharsets.UTF_8)),
                (StandardCharsets.UTF_8));
    }
    
    InboundAuthenticationRequestConfig updateSAMLInbound(ServiceProvider application,
                                                      SAML2ProtocolConfigDTO saml2ProtocolConfigDTO)
            throws IdentitySAML2SSOException {
        
        // First we identify whether this is a insert or update.
        Optional<String> optionalInboundAuthKey = getInboundAuthKey(application, SAML2);
        InboundAuthenticationRequestConfig updatedInbound;
        if (optionalInboundAuthKey.isPresent()) {
            // This is an update.
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = updateSamlSSoServiceProviderDTO(
                    saml2ProtocolConfigDTO, optionalInboundAuthKey.get());
            
            // Set certificate if available.
            if (samlssoServiceProviderDTO.getCertificateContent() != null) {
                application.setCertificateContent(base64Encode(samlssoServiceProviderDTO.getCertificateContent()));
            }
            updatedInbound = createInboundAuthenticationRequestConfig(samlssoServiceProviderDTO);
        } else {
            updatedInbound = createSAMLInbound(application, saml2ProtocolConfigDTO);
        }
        return updatedInbound;
    }
    
    private static SAMLSSOServiceProviderDTO updateSamlSSoServiceProviderDTO(
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO, String currentIssuer)
            throws IdentitySAML2SSOException {
        
        SAMLSSOServiceProviderDTO samlManualConfiguration = saml2ProtocolConfigDTO.getManualConfiguration();
        
        if (saml2ProtocolConfigDTO.getMetadataFile() != null) {
            return updateSAMLSpWithMetadataFile(saml2ProtocolConfigDTO.getMetadataFile(), currentIssuer);
        } else if (saml2ProtocolConfigDTO.getMetadataURL() != null) {
            return updateSAMLSpWithMetadataUrl(saml2ProtocolConfigDTO.getMetadataURL(), currentIssuer);
        } else if (samlManualConfiguration != null) {
            return updateSAMLSpWithManualConfiguration(samlManualConfiguration, currentIssuer);
        } else {
            throw new IdentitySAML2ClientException("Invalid SAML2 Configuration. One of metadataFile, metaDataUrl or " +
                    "serviceProvider manual configuration needs to be present.");
        }
    }
    
    private static SAMLSSOServiceProviderDTO updateSAMLSpWithMetadataFile(String encodedMetaFileContent,
                                                                          String currentIssuer)
            throws IdentitySAML2SSOException {
        
        byte[] metaData = Base64.getDecoder().decode(encodedMetaFileContent.getBytes(StandardCharsets.UTF_8));
        String base64DecodedMetadata = new String(metaData, StandardCharsets.UTF_8);
        
        return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService()
                .updateRPServiceProviderWithMetadata(base64DecodedMetadata, currentIssuer, false);
    }
    
    private static SAMLSSOServiceProviderDTO updateSAMLSpWithMetadataUrl(String metadataUrl, String currentIssuer)
            throws IdentitySAML2SSOException {
        
        return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService()
                .updateServiceProviderWithMetadataURL(metadataUrl, currentIssuer, false);
    }
    
    private static SAMLSSOServiceProviderDTO updateSAMLSpWithManualConfiguration(
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO, String currentIssuer)
            throws IdentitySAML2SSOException {
        try {
            return IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlSSOConfigService().updateServiceProvider(
                    samlssoServiceProviderDTO, currentIssuer, false);
        } catch (IdentityException e) {
            // The above service always returns exception with error code, error message and cause.
            throw handleException(e.getMessage(), e);
        }
    }
    
    private static InboundAuthenticationRequestConfig createInboundAuthenticationRequestConfig(
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO) throws IdentitySAML2SSOException {
        
        InboundAuthenticationRequestConfig samlInbound = new InboundAuthenticationRequestConfig();
        samlInbound.setInboundAuthType(FrameworkConstants.StandardInboundProtocols.SAML2);
        samlInbound.setInboundAuthKey(samlssoServiceProviderDTO.getIssuer());
        if (samlssoServiceProviderDTO.isEnableAttributeProfile()) {
            Property[] properties = new Property[1];
            Property property = new Property();
            property.setName(ATTRIBUTE_CONSUMING_SERVICE_INDEX);
            if (StringUtils.isNotBlank(samlssoServiceProviderDTO.getAttributeConsumingServiceIndex())) {
                property.setValue(samlssoServiceProviderDTO.getAttributeConsumingServiceIndex());
            } else {
                try {
                    property.setValue(Integer.toString(IdentityUtil.getRandomInteger()));
                } catch (IdentityException e) {
                    throw handleException(e.getMessage(), e);
                }
            }
            properties[0] = property;
            samlInbound.setProperties(properties);
        }
        samlInbound.setData(SAMLSSOUtil.buildSPDataFromJsonString(samlssoServiceProviderDTO.getAuditLogData()));
        return samlInbound;
    }
    
    private static IdentitySAML2SSOException handleException(String message, IdentityException ex) {
        
        if (ex instanceof IdentitySAML2ClientException) {
            return (IdentitySAML2ClientException) ex;
        } else if (ex instanceof IdentitySAML2SSOException) {
            return (IdentitySAML2SSOException) ex;
        }
        else {
            return new IdentitySAML2SSOException(ex.getErrorCode(), message, ex);
        }
    }
}
