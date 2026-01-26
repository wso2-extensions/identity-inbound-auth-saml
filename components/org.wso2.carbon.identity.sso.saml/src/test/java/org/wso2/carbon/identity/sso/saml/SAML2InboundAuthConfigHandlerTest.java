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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.inbound.dto.InboundProtocolsDTO;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.internal.component.IdentityCoreServiceComponent;
import org.wso2.carbon.identity.organization.management.service.exception.OrganizationManagementException;
import org.wso2.carbon.identity.organization.management.service.util.OrganizationManagementUtil;
import org.wso2.carbon.identity.sso.saml.dto.SAML2ProtocolConfigDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.io.File;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SAML2InboundAuthConfigHandlerTest {

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

    private AutoCloseable mocksHandle;

    private static final String ISSUER = "Issuer_01";
    private static final String APPLICATION_NAME = "dummyApplication";
    private static final String APPLICATION_RESOURCE_ID = "dummyResourceId";
    private static final String META_DATA_URL = "https://localhost:9443/identity/metadata/saml2";
    private static final String TENANT_DOMAIN = "tenantDomain";

    @BeforeMethod
    public void setUp() throws Exception {

        mocksHandle = MockitoAnnotations.openMocks(this);
        System.setProperty("carbon.home",
                System.getProperty("user.dir") + File.separator + "src" + File.separator + "test"
                        + File.separator + "resources");

        initConfigsAndRealm();
    }
    
    @AfterMethod
    public void tearDown() throws Exception {

        mocksHandle.close();
    }

    @DataProvider(name = "organizationDataProvider")
    public Object[][] organizationDataProvider() {

        return new Object[][]{
                {true, false},
                {false, true}
        };
    }

    @Test(dataProvider = "organizationDataProvider")
    public void testCanHandle(boolean isOrganization, boolean expected) throws Exception{

        try (MockedStatic<PrivilegedCarbonContext> pcc = Mockito.mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<OrganizationManagementUtil> orgUtil = Mockito.mockStatic(OrganizationManagementUtil.class)) {
            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            pcc.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
            orgUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString())).thenReturn(isOrganization);

            InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
            inboundProtocolsDTO.addProtocolConfiguration(saml2ProtocolConfigDTO);

            Assert.assertEquals(saml2InboundAuthConfigHandler.canHandle(inboundProtocolsDTO), expected);
        }
    }

    @Test(expectedExceptions = IdentityRuntimeException.class)
    public void testCanHandleWithException() throws Exception {

        try (MockedStatic<PrivilegedCarbonContext> pcc = Mockito.mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<OrganizationManagementUtil> orgUtil = Mockito.mockStatic(OrganizationManagementUtil.class)) {
            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            pcc.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
            orgUtil.when(() -> OrganizationManagementUtil.isOrganization(anyString()))
                    .thenThrow(OrganizationManagementException.class);

            InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
            inboundProtocolsDTO.addProtocolConfiguration(saml2ProtocolConfigDTO);

            saml2InboundAuthConfigHandler.canHandle(inboundProtocolsDTO);
        }
    }

    @Test
    public void testCreateInboundSAML2Protocol() throws Exception {

        try (MockedStatic<IdentitySAMLSSOServiceComponentHolder> holder =
                     Mockito.mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            holder.when(IdentitySAMLSSOServiceComponentHolder::getInstance).thenReturn(samlssoServiceComponentHolder);
            when(samlssoServiceComponentHolder.getSamlSSOConfigService()).thenReturn(samlssoConfigService);

            mockServiceProvider(false);

            InboundProtocolsDTO inboundProtocolsDTO = new InboundProtocolsDTO();
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();

            saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);
            inboundProtocolsDTO.addProtocolConfiguration(saml2ProtocolConfigDTO);

            SAMLSSOServiceProviderDTO updatedSAMLSSOServiceProviderDTO = new SAMLSSOServiceProviderDTO();
            updatedSAMLSSOServiceProviderDTO.setAuditLogData(getDummyAuditLogData());

            when(samlssoConfigService.createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false)))
                    .thenReturn(updatedSAMLSSOServiceProviderDTO);

            InboundAuthenticationRequestConfig result = saml2InboundAuthConfigHandler.handleConfigCreation(application,
                    inboundProtocolsDTO);

            verify(samlssoConfigService, times(0)).createServiceProviderWithMetadataURL(eq(META_DATA_URL));
            verify(samlssoConfigService, times(1)).createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false));

            Assert.assertFalse(result.getData().isEmpty());
            Assert.assertEquals(result.getInboundAuthType(), FrameworkConstants.StandardInboundProtocols.SAML2);
        }
    }

    @Test
    public void testUpdateSAML2Protocol() throws Exception {

        try (MockedStatic<PrivilegedCarbonContext> pcc = Mockito.mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<IdentitySAMLSSOServiceComponentHolder> holder =
                     Mockito.mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            pcc.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
            holder.when(IdentitySAMLSSOServiceComponentHolder::getInstance).thenReturn(samlssoServiceComponentHolder);
            when(samlssoServiceComponentHolder.getSamlSSOConfigService()).thenReturn(samlssoConfigService);

            mockServiceProvider(true);

            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
            samlssoServiceProviderDTO.setAuditLogData(getDummyAuditLogData());
            samlssoServiceProviderDTO.setIssuer(ISSUER);

            when(samlssoConfigService.updateServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(ISSUER), eq(false)))
                    .thenReturn(samlssoServiceProviderDTO);
            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
            saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);
            saml2InboundAuthConfigHandler.handleConfigUpdate(application, saml2ProtocolConfigDTO);

            verify(samlssoConfigService, times(1)).updateServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(ISSUER),
                    eq(false));
            verify(samlssoConfigService, times(0)).updateServiceProviderWithMetadataURL(any(), any(), eq(true));
        }
    }

    @Test
    public void testUpdateSAML2Protocol_CreateNewApplication() throws Exception {

        try (MockedStatic<IdentitySAMLSSOServiceComponentHolder> holder =
                     Mockito.mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            holder.when(IdentitySAMLSSOServiceComponentHolder::getInstance).thenReturn(samlssoServiceComponentHolder);
            when(samlssoServiceComponentHolder.getSamlSSOConfigService()).thenReturn(samlssoConfigService);

            mockServiceProvider(false);

            SAMLSSOServiceProviderDTO updatedSAMLServiceProvider = new SAMLSSOServiceProviderDTO();
            updatedSAMLServiceProvider.setIssuer(ISSUER);
            updatedSAMLServiceProvider.setAuditLogData(getDummyAuditLogData());
            when(samlssoConfigService.createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false)))
                    .thenReturn(updatedSAMLServiceProvider);

            SAML2ProtocolConfigDTO saml2ProtocolConfigDTO = new SAML2ProtocolConfigDTO();
            saml2ProtocolConfigDTO.setMetadataURL(META_DATA_URL);

            InboundAuthenticationRequestConfig result = saml2InboundAuthConfigHandler.handleConfigUpdate(application,
                    saml2ProtocolConfigDTO);

            verify(samlssoConfigService, times(1)).createServiceProviderWithMetadataURL(eq(META_DATA_URL), eq(false));
            verify(samlssoConfigService, times(0)).createServiceProviderWithMetadataURL(any(), eq(true));
            Assert.assertFalse(result.getData().isEmpty());
        }
    }

    @Test
    public void testDeleteSAML2Inbound() throws Exception {

        try (MockedStatic<PrivilegedCarbonContext> pcc = Mockito.mockStatic(PrivilegedCarbonContext.class);
             MockedStatic<IdentitySAMLSSOServiceComponentHolder> holder =
                     Mockito.mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            PrivilegedCarbonContext privilegedCarbonContext = mock(PrivilegedCarbonContext.class);
            pcc.when(PrivilegedCarbonContext::getThreadLocalCarbonContext).thenReturn(privilegedCarbonContext);
            when(privilegedCarbonContext.getTenantDomain()).thenReturn(TENANT_DOMAIN);
            holder.when(IdentitySAMLSSOServiceComponentHolder::getInstance).thenReturn(samlssoServiceComponentHolder);
            when(samlssoServiceComponentHolder.getSamlSSOConfigService()).thenReturn(samlssoConfigService);

            saml2InboundAuthConfigHandler.handleConfigDeletion(ISSUER);

            verify(samlssoConfigService, times(1)).removeServiceProvider(eq(ISSUER), eq(false));
            verify(samlssoConfigService, times(0)).removeServiceProvider(eq(ISSUER), eq(true));
        }
    }

    private void initConfigsAndRealm() throws Exception {

        IdentityCoreServiceComponent identityCoreServiceComponent = new IdentityCoreServiceComponent();
        ConfigurationContextService configurationContextService = new ConfigurationContextService
                (configurationContext, null);
        // Replace Mockito internal FieldSetter with reflection to set private field
        Field field = identityCoreServiceComponent.getClass().getDeclaredField("configurationContextService");
        field.setAccessible(true);
        field.set(identityCoreServiceComponent, configurationContextService);
        when(configurationContext.getAxisConfiguration()).thenReturn(axisConfiguration);
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
        Map<String, Object> dummyMap = getDummyMap();
        return gson.toJson(dummyMap);
    }
}
