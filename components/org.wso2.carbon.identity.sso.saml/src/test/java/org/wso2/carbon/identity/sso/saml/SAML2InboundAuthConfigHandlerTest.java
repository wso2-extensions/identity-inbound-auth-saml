/*
 * Copyright (c) 2023, WSO2 LLC. (http://www.wso2.com).
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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.engine.AxisConfiguration;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.internal.util.reflection.FieldSetter;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.core.internal.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ProtocolConfigDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.powermock.api.mockito.PowerMockito.mock;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;

@PrepareForTest({IdentitySAMLSSOServiceComponentHolder.class, PrivilegedCarbonContext.class})
public class SAML2InboundAuthConfigHandlerTest extends PowerMockTestCase {
    
    @Mock
    private ConfigurationContext configurationContext;
    @Mock
    private AxisConfiguration axisConfiguration;
    @Mock
    private IdentitySAMLSSOServiceComponentHolder samlssoServiceComponentHolder;
    @Mock
    private SAMLSSOConfigServiceImpl samlssoConfigService;
    @InjectMocks
    private SAML2InboundAuthConfigHandler saml2InboundAuthConfigHandler;
    @Mock
    private ServiceProvider application;
    
    private static final String ISSUER = "Issuer_01";
    private static final String APPLICATION_NAME = "dummyApplication";
    private static final String APPLICATION_RESOURCE_ID = "dummyResourceId";
    private static final String META_DATA_URL = "https://localhost:9443/identity/metadata/saml2";
    
    @BeforeMethod
    public void setUp() throws Exception {
        
        MockitoAnnotations.initMocks(this);
        System.setProperty("carbon.home",
                System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources");
        
        initConfigsAndRealm();
    }
    
    @Test
    public void testCreateInboundSAML2Protocol() throws Exception {
        
        mockSAMLSSOServiceComponentHolder();
        mockServiceProvider(false);
        
        InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
        SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
        
        saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);
        inboundProtocolsDTO.addProtocolConfiguration(saml2ProtocolConfigDTO);
        
        SAMLSSOServiceProviderDTO updatedSAMLSSOServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        updatedSAMLSSOServiceProviderDTO.setAuditLogData(getDummyAuditLogData());
        
        when(samlssoConfigService.createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false)))
                .thenReturn(updatedSAMLSSOServiceProviderDTO);
        
        // We don't need the service provider object for OAuth protocol creation.
        InboundAuthenticationRequestConfig result = saml2InboundAuthConfigHandler.handleConfigCreation(application,
                inboundProtocolsDTO);
        
        // Verify that the OAuthAdminService is called with the correct parameters.
        verify(samlssoConfigService, times(0)).createServiceProviderWithMetadataURL(eq(META_DATA_URL));
        verify(samlssoConfigService, times(1)).createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false));
        
        // Asserting the audit log data is added to the result.
        Assert.assertFalse(result.getData().isEmpty());
        Assert.assertEquals(result.getInboundAuthType(), FrameworkConstants.StandardInboundProtocols.SAML2);
    }
    
    @Test
    public void testUpdateSAML2Protocol() throws Exception {
        
        mockPrivilegeCarbonContext();
        mockSAMLSSOServiceComponentHolder();
        mockServiceProvider(true);
        
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setAuditLogData(getDummyAuditLogData());
        samlssoServiceProviderDTO.setIssuer(ISSUER);
        
        // Mock behavior when currentClientId is not null, indicating an existing application.
        when(samlssoConfigService.updateServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(ISSUER), eq(false)))
                .thenReturn(samlssoServiceProviderDTO);
        SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
        saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);
        saml2InboundAuthConfigHandler.handleConfigUpdate(application, saml2ProtocolConfigDTO);
        
        // Verify that SAML service provider is updated without the audit logs.
        verify(samlssoConfigService, times(1)).updateServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(ISSUER),
                eq(false));
        verify(samlssoConfigService, times(0)).updateServiceProviderWithMetadataURL(any(), any(), eq(true));
    }
    
    @Test
    public void testUpdateSAML2Protocol_CreateNewApplication() throws Exception {
        
        mockSAMLSSOServiceComponentHolder();
        mockServiceProvider(false);
        
        SAMLSSOServiceProviderDTO updatedSAMLServiceProvider = new SAMLSSOServiceProviderDTO();
        updatedSAMLServiceProvider.setIssuer(ISSUER);
        updatedSAMLServiceProvider.setAuditLogData(getDummyAuditLogData());
        when(samlssoConfigService.createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false)))
                .thenReturn(updatedSAMLServiceProvider);
        
        // Mock behavior when currentClientId is null, indicating a new application
        SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
        saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);
        
        InboundAuthenticationRequestConfig result = saml2InboundAuthConfigHandler.handleConfigUpdate(application,
                saml2ProtocolConfigDTO);
        
        // Verify that SAML service provider is updated without the audit logs.
        verify(samlssoConfigService, times(1)).createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false));
        verify(samlssoConfigService, times(0)).createServiceProviderWithMetadataURL(any(), eq(true));
        Assert.assertFalse(result.getData().isEmpty());
    }
    
    @Test
    public void testDeleteSAML2Inbound() throws Exception {
        
        mockPrivilegeCarbonContext();
        mockSAMLSSOServiceComponentHolder();
        
        saml2InboundAuthConfigHandler.handleConfigDeletion(ISSUER);
        
        // Verify that SAML service provider is deleted without the audit logs.
        verify(samlssoConfigService, times(1)).removeServiceProvider(eq(ISSUER), eq(false));
        verify(samlssoConfigService, times(0)).removeServiceProvider(eq(ISSUER), eq(true));
    }
    
    private void initConfigsAndRealm() throws Exception {
        
        IdentityCoreServiceComponent identityCoreServiceComponent = new IdentityCoreServiceComponent();
        ConfigurationContextService configurationContextService = new ConfigurationContextService
                (configurationContext, null);
        FieldSetter.setField(identityCoreServiceComponent, identityCoreServiceComponent.getClass().
                getDeclaredField("configurationContextService"), configurationContextService);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);
    }
    
    private void mockSAMLSSOServiceComponentHolder() {
        
        mockStatic(IdentitySAMLSSOServiceComponentHolder.class);
        Mockito.when(IdentitySAMLSSOServiceComponentHolder.getInstance()).thenReturn(samlssoServiceComponentHolder);
        when(samlssoServiceComponentHolder.getSamlSSOConfigService()).thenReturn(samlssoConfigService);
    }
    
    private void mockPrivilegeCarbonContext() {
        
        mockStatic(PrivilegedCarbonContext.class);
        PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
        when(PrivilegedCarbonContext.getThreadLocalCarbonContext()).thenReturn(privilegedCarbonContext);
    }
    
    private void mockServiceProvider(boolean setInboundAuthConfig) {
        
        this.application = new ServiceProvider();
        application.setApplicationName(APPLICATION_NAME);
        application.setApplicationResourceId(APPLICATION_RESOURCE_ID);
        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        if(setInboundAuthConfig) {
            InboundAuthenticationRequestConfig inboundAuthConfig = new InboundAuthenticationRequestConfig();
            inboundAuthConfig.setInboundAuthKey(ISSUER);
            inboundAuthConfig.setInboundAuthType(FrameworkConstants.StandardInboundProtocols.SAML2);
            inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(new InboundAuthenticationRequestConfig[]{
                    inboundAuthConfig
            });
            application.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        }
    }
    
    private Map<String, Object> getDummyMap() {
        
        Map<String, Object> dummyMap = new HashMap<>();
        dummyMap.put("issuer", ISSUER);
        return dummyMap;
    }

    private String getDummyAuditLogData() {

        Gson gson = new Gson();
        String json = gson.toJson(getDummyMap());
        return gson.fromJson(json, new TypeToken<Map<String, Object>>() {
        }.getType());
    }
}
