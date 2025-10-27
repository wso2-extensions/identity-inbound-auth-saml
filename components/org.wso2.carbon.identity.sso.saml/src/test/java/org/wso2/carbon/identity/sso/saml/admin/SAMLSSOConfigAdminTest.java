/*
 * Copyright (c) (2017-2023), WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.sso.saml.admin;

import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class SAMLSSOConfigAdminTest {

    private SAMLSSOConfigAdmin samlssoConfigAdmin;

    @Mock
    UserRegistry userRegistry;

    @Mock
    IdentityUtil identityUtil;

    @Mock
    private SAMLSSOServiceProviderManager samlSSOServiceProviderManager;

    @Mock
    IdentitySAMLSSOServiceComponentHolder identitySAMLSSOServiceComponentHolder;

    @Mock(serializable = true)
    SAMLSSOServiceProviderDO samlssoServiceProvDO;

    @Mock
    SSOServiceProviderConfigManager ssoServiceProviderConfigManager;

    @Mock
    Parser parser;

    private AutoCloseable openMocks;
    private MockedStatic<IdentitySAMLSSOServiceComponentHolder> identitySAMLSSOServiceComponentHolderStatic;

    @BeforeMethod
    public void setUp() throws Exception {

        openMocks = MockitoAnnotations.openMocks(this);
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        samlssoConfigAdmin = new SAMLSSOConfigAdmin(userRegistry);
        identitySAMLSSOServiceComponentHolderStatic = Mockito.mockStatic(
                IdentitySAMLSSOServiceComponentHolder.class);
        identitySAMLSSOServiceComponentHolderStatic.when(
                        IdentitySAMLSSOServiceComponentHolder::getInstance)
                .thenReturn(identitySAMLSSOServiceComponentHolder);
        when(identitySAMLSSOServiceComponentHolder.getSAMLSSOServiceProviderManager())
                .thenReturn(samlSSOServiceProviderManager);
    }

    @AfterMethod
    public void tearDown() throws Exception {

        if (identitySAMLSSOServiceComponentHolderStatic != null) {
            identitySAMLSSOServiceComponentHolderStatic.close();
            identitySAMLSSOServiceComponentHolderStatic = null;
        }
        if (openMocks != null) {
            openMocks.close();
        }
    }

    @Test
    public void testAddRelyingPartyServiceProvider() throws IdentityException {

        try (MockedStatic<SSOServiceProviderConfigManager> sspCfgStatic = Mockito.mockStatic(
                SSOServiceProviderConfigManager.class)) {
            sspCfgStatic.when(SSOServiceProviderConfigManager::getInstance)
                    .thenReturn(ssoServiceProviderConfigManager);
            when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                    .thenReturn(true);
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
            samlssoServiceProviderDTO.setIssuer("testUser");

            Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), true);
            samlssoServiceProvDO = new SAMLSSOServiceProviderDO();
            when(ssoServiceProviderConfigManager.getServiceProvider("testUser")).thenReturn(samlssoServiceProvDO);
            Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), false);
        }
    }

    @Test
    public void testUpdateRelyingPartyServiceProvider() throws IdentityException {

        try (MockedStatic<SSOServiceProviderConfigManager> sspCfgStatic = Mockito.mockStatic(
                SSOServiceProviderConfigManager.class)) {
            sspCfgStatic.when(SSOServiceProviderConfigManager::getInstance)
                    .thenReturn(ssoServiceProviderConfigManager);
            when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                    .thenReturn(true);
            SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
            samlssoServiceProviderDTO.setIssuer("testUser");

            Assert.assertEquals(samlssoConfigAdmin.updateRelyingPartyServiceProvider(samlssoServiceProviderDTO, "testUser"), true);
            samlssoServiceProvDO = new SAMLSSOServiceProviderDO();
            when(ssoServiceProviderConfigManager.getServiceProvider("testUser")).thenReturn(samlssoServiceProvDO);
            Assert.assertEquals(samlssoConfigAdmin.updateRelyingPartyServiceProvider(samlssoServiceProviderDTO, "testUser"), false);
        }
    }

    @DataProvider(name = "dataProviders")
    public Object[][] values() {

        return new Object[][]{
                {null},
                {""},
                {"user@example.com"}
        };
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testCreateSAMLSSOServiceProviderDO(String issuer) throws Exception {

        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer(issuer);
        Assert.assertTrue(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO));
    }

    @Test(expectedExceptions = IdentitySAML2ClientException.class)
    public void testCreateSAMLSSOServiceProviderDOWithInvalidIssuerQualifier() throws Exception {

        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer("travelocity.com");
        // Qualifier cannot have '@'.
        samlssoServiceProviderDTO.setIssuerQualifier("something@qualifier");
        samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO);
    }

    @Test
    public void testUploadRelyingPartyServiceProvider() throws Exception {

        String metadata = "metadata";
        try (MockedStatic<SAMLSSOUtil> utilStatic = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                     when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                         SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                         spdo.setIssuer("issuer");
                         return spdo;
                     }))) {
            utilStatic.when(() -> SAMLSSOUtil.buildSPDataJSONString(any())).thenReturn("spDataJSONString");
            utilStatic.when(() -> SAMLSSOUtil.buildSPData(any())).thenReturn(Collections.emptyMap());
            when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                    .thenReturn(true);

            Assert.assertNotNull(samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata));
        }
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUploadRelyingPartyServiceProvider1() throws Exception {

        String metadata = "metadata";
        try (MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                    SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                    spdo.setIssuer("issuer");
                    return spdo;
                }))) {
            when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                    .thenReturn(false);
            samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata);
        }
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testUploadRelyingPartyServiceProvider2(String issuer) throws Exception {

        String metadata = "metadata";
        try (MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                    SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                    spdo.setIssuer(issuer);
                    return spdo;
                }))) {
            when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                    .thenReturn(true);
            Assert.assertNotNull(samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata));
        }
    }

    @Test
    public void testUpdateRelyingPartyServiceProviderWithMetadata() throws Exception {

        String metadata = "metadata";
        try (MockedStatic<SAMLSSOUtil> utilStatic = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<SSOServiceProviderConfigManager> sspCfgStatic = Mockito.mockStatic(
                     SSOServiceProviderConfigManager.class);
             MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                     when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                         SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                         spdo.setIssuer("issuer");
                         return spdo;
                     }))) {
            utilStatic.when(() -> SAMLSSOUtil.buildSPDataJSONString(any())).thenReturn("spDataJSONString");
            utilStatic.when(() -> SAMLSSOUtil.buildSPData(any())).thenReturn(Collections.emptyMap());
            when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                    .thenReturn(true);
            sspCfgStatic.when(SSOServiceProviderConfigManager::getInstance)
                    .thenReturn(ssoServiceProviderConfigManager);

            Assert.assertNotNull(samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "issuer"));
        }
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUpdateRelyingPartyServiceProviderWithMetadata1() throws Exception {

        String metadata = "metadata";
        try (MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                    SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                    spdo.setIssuer("issuer");
                    return spdo;
                }))) {
            when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                    .thenReturn(false);
            samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "issuer");
        }
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testUpdateRelyingPartyServiceProviderWithMetadata2(String issuer) throws Exception {

        String metadata = "metadata";
        try (MockedConstruction<Parser> parserConstruction = Mockito.mockConstruction(Parser.class, (mock, context) ->
                when(mock.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenAnswer(invocation -> {
                    SAMLSSOServiceProviderDO spdo = invocation.getArgument(1);
                    spdo.setIssuer(issuer);
                    return spdo;
                }))) {
            when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                    .thenReturn(true);
            Assert.assertNotNull(samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "testUser"));
        }
    }

    @Test
    public void testGetServiceProviders() throws Exception {

        SAMLSSOServiceProviderDO[] serviceProvidersList = new SAMLSSOServiceProviderDO[3];
        when(userRegistry.getTenantId()).thenReturn(0);
        when(samlSSOServiceProviderManager.getServiceProviders(anyInt())).thenReturn(serviceProvidersList);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer("issuer");
        SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO1.setIssuer("issuer1");
        samlssoServiceProviderDO1.setLoginPageURL("https://locahost:8080/travelocity.com/login.jsp");
        SAMLSSOServiceProviderDO samlssoServiceProviderDO2 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO2.setLoginPageURL("null");
        samlssoServiceProviderDO2.setNameIDFormat("user@tenantDomain");
        serviceProvidersList[0] = samlssoServiceProviderDO;
        serviceProvidersList[1] = samlssoServiceProviderDO1;
        serviceProvidersList[2] = samlssoServiceProviderDO2;

        when(userRegistry.getTenantId()).thenReturn(0);
        Assert.assertEquals(samlssoConfigAdmin.getServiceProviders().getServiceProviders().length, 3);
        when(userRegistry.getTenantId()).thenReturn(1);
        Assert.assertEquals(samlssoConfigAdmin.getServiceProviders().getServiceProviders().length, 3);
    }

    @Test
    public void testGetServiceProvidersForValidNameIDFormat() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilStatic = Mockito.mockStatic(IdentityUtil.class)) {
            SAMLSSOServiceProviderDO[] serviceProvidersList = new SAMLSSOServiceProviderDO[2];
            when(userRegistry.getTenantId()).thenReturn(0);
            when(samlSSOServiceProviderManager.getServiceProviders(anyInt())).thenReturn(serviceProvidersList);

            SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
            samlssoServiceProviderDO.setIssuer("issuer");
            samlssoServiceProviderDO.setNameIDFormat(null);
            SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
            samlssoServiceProviderDO1.setIssuer("issuer1");
            samlssoServiceProviderDO1.setNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            serviceProvidersList[0] = samlssoServiceProviderDO;
            serviceProvidersList[1] = samlssoServiceProviderDO1;

            identityUtilStatic.when(() -> IdentityUtil.getProperty(SAMLSSOConstants.SAML_RETURN_VALID_NAME_ID_FORMAT))
                    .thenReturn("true");

            when(userRegistry.getTenantId()).thenReturn(0);
            SAMLSSOServiceProviderDTO[] serviceProviders = samlssoConfigAdmin.getServiceProviders().getServiceProviders();
            Assert.assertEquals(serviceProviders.length, 2);
            Assert.assertEquals(serviceProviders[0].getNameIDFormat(),
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            Assert.assertEquals(serviceProviders[1].getNameIDFormat(),
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        }
    }

    @Test
    public void testGetServiceProvidersForLegacyNameIDFormat() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilStatic = Mockito.mockStatic(IdentityUtil.class)) {
            SAMLSSOServiceProviderDO[] serviceProvidersList = new SAMLSSOServiceProviderDO[2];
            when(userRegistry.getTenantId()).thenReturn(0);
            when(samlSSOServiceProviderManager.getServiceProviders(anyInt())).thenReturn(serviceProvidersList);

            SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
            samlssoServiceProviderDO.setIssuer("issuer");
            samlssoServiceProviderDO.setNameIDFormat(null);
            SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
            samlssoServiceProviderDO1.setIssuer("issuer1");
            samlssoServiceProviderDO1.setNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
            serviceProvidersList[0] = samlssoServiceProviderDO;
            serviceProvidersList[1] = samlssoServiceProviderDO1;

            identityUtilStatic.when(() -> IdentityUtil.getProperty(SAMLSSOConstants.SAML_RETURN_VALID_NAME_ID_FORMAT))
                    .thenReturn("false");

            when(userRegistry.getTenantId()).thenReturn(0);
            SAMLSSOServiceProviderDTO[] serviceProviders = samlssoConfigAdmin.getServiceProviders().getServiceProviders();
            Assert.assertEquals(serviceProviders.length, 2);
            Assert.assertEquals(serviceProviders[0].getNameIDFormat(),
                    "urn/oasis/names/tc/SAML/1.1/nameid-format/unspecified");
            Assert.assertEquals(serviceProviders[1].getNameIDFormat(),
                    "urn/oasis/names/tc/SAML/1.1/nameid-format/emailAddress");
        }
    }
}
