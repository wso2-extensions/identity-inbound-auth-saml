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

package org.wso2.carbon.identity.sso.saml.dto;

import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolConfigurationDTO;

import java.util.Map;

/**
 * SAML2 Inbound Protocol Configuration DTO.
 */
public class SAML2ProtocolConfigDTO implements InboundProtocolConfigurationDTO {
    
    private SAMLSSOServiceProviderDTO manualConfiguration;
    private String metadataFile;
    private String metadataURL;
    private Map<String, Object> auditLogData;
    
    public SAMLSSOServiceProviderDTO getManualConfiguration() {
        
        return manualConfiguration;
    }
    
    /**
     * Set manual configuration.
     *
     * @param manualConfiguration Manual configuration.
     */
    public void setManualConfiguration(SAMLSSOServiceProviderDTO manualConfiguration) {
        
        this.manualConfiguration = manualConfiguration;
    }
    
    /**
     * Get metadata file.
     *
     * @return Metadata file.
     */
    public String getMetadataFile() {
        
        return metadataFile;
    }
    
    /**
     * Set metadata file.
     *
     * @param metadataFile Metadata file.
     */
    public void setMetadataFile(String metadataFile) {
        
        this.metadataFile = metadataFile;
    }
    
    /**
     * Get metadata URL.
     *
     * @return Metadata URL.
     */
    public String getMetadataURL() {
        
        return metadataURL;
    }
    
    /**
     * Set metadata URL.
     *
     * @param metadataURL Metadata URL.
     */
    public void setMetadataURL(String metadataURL) {
        
        this.metadataURL = metadataURL;
    }
    
    /**
     * Get audit log data.
     *
     * @return Audit log data.
     */
    public Map<String, Object> getAuditLogData() {
        
        return auditLogData;
    }
    
    /**
     * Set audit log data.
     *
     * @param auditLogData Audit log data.
     */
    public void setAuditLogData(Map<String, Object> auditLogData) {
        
        this.auditLogData = auditLogData;
    }
    
    /**
     * Get protocol name.
     *
     * @return Protocol name.
     */
    @Override
    public String fetchProtocolName() {
        
        return ApplicationConstants.StandardInboundProtocols.SAML2;
    }
}
