package org.wso2.carbon.identity.sso.saml.dto;

import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolConfigurationDTO;

import java.util.Map;

public class SAML2ProtocolConfigDTO implements InboundProtocolConfigurationDTO {
    
    private SAMLSSOServiceProviderDTO manualConfiguration;
    private String metadataFile;
    private String metadataURL;
    private Map<String, Object> auditLogData;
    
    public SAMLSSOServiceProviderDTO getManualConfiguration() {
        
        return manualConfiguration;
    }
    
    public void setManualConfiguration(SAMLSSOServiceProviderDTO manualConfiguration) {
        
        this.manualConfiguration = manualConfiguration;
    }
    
    public String getMetadataFile() {
        
        return metadataFile;
    }
    
    public void setMetadataFile(String metadataFile) {
        
        this.metadataFile = metadataFile;
    }
    
    public String getMetadataURL() {
        
        return metadataURL;
    }
    
    public void setMetadataURL(String metadataURL) {
        
        this.metadataURL = metadataURL;
    }
    
    public Map<String, Object> getAuditLogData() {
        
        return auditLogData;
    }
    
    public void setAuditLogData(Map<String, Object> auditLogData) {
        
        this.auditLogData = auditLogData;
    }
    
    @Override
    public String getProtocolName() {
        
        return ApplicationConstants.StandardInboundProtocols.SAML2;
    }
}
