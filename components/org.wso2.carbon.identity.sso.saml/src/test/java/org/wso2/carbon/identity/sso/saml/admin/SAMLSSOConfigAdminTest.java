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
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
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
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({IdentitySAMLSSOServiceComponentHolder.class, SSOServiceProviderConfigManager.class,
        SAMLSSOServiceProviderDO.class, Parser.class, UserRegistry.class, SAMLSSOConfigAdmin.class, SAMLSSOUtil.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.apache.xerces.*", "org.w3c.dom.*"})
public class SAMLSSOConfigAdminTest extends PowerMockTestCase {

    private SAMLSSOConfigAdmin samlssoConfigAdmin;

    @Mock
    UserRegistry userRegistry;

    @Mock
    private SAMLSSOServiceProviderManager samlSSOServiceProviderManager;

    @Mock IdentitySAMLSSOServiceComponentHolder identitySAMLSSOServiceComponentHolder;

    @Mock(serializable = true)
    SAMLSSOServiceProviderDO samlssoServiceProvDO;

    @Mock
    SSOServiceProviderConfigManager ssoServiceProviderConfigManager;

    @Mock
    Parser parser;
    
    @BeforeMethod
    public void setUp() throws Exception {
        
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        samlssoConfigAdmin = new SAMLSSOConfigAdmin(userRegistry);
        mockStatic(IdentitySAMLSSOServiceComponentHolder.class);
        when(IdentitySAMLSSOServiceComponentHolder.getInstance())
                .thenReturn(identitySAMLSSOServiceComponentHolder);
        when(identitySAMLSSOServiceComponentHolder.getSAMLSSOServiceProviderManager())
                .thenReturn(samlSSOServiceProviderManager);
        mockStatic(SAMLSSOServiceProviderDO.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testAddRelyingPartyServiceProvider() throws IdentityException {

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                .thenReturn(true);
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer("testUser");

        Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), true);
        samlssoServiceProvDO = new SAMLSSOServiceProviderDO();
        when(ssoServiceProviderConfigManager.getServiceProvider("testUser")).thenReturn(samlssoServiceProvDO);
        Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), false);
    }

    @Test
    public void testUpdateRelyingPartyServiceProvider() throws IdentityException {

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                .thenReturn(true);
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer("testUser");

        Assert.assertEquals(samlssoConfigAdmin.updateRelyingPartyServiceProvider(samlssoServiceProviderDTO, "testUser"), true);
        samlssoServiceProvDO = new SAMLSSOServiceProviderDO();
        when(ssoServiceProviderConfigManager.getServiceProvider("testUser")).thenReturn(samlssoServiceProvDO);
        Assert.assertEquals(samlssoConfigAdmin.updateRelyingPartyServiceProvider(samlssoServiceProviderDTO, "testUser"), false);
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
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.buildSPDataJSONString(any())).thenReturn("spDataJSONString");
        when(SAMLSSOUtil.buildSPData(any())).thenReturn(Collections.emptyMap());
        when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                .thenReturn(true);
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn("issuer");
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        Assert.assertNotNull(samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata));

    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUploadRelyingPartyServiceProvider1() throws Exception {

        String metadata = "metadata";
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn("issuer");
        when(samlSSOServiceProviderManager.addServiceProvider(samlssoServiceProvDO, userRegistry.getTenantId()))
                .thenReturn(false);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata);
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testUploadRelyingPartyServiceProvider2(String issuer) throws Exception {

        String metadata = "metadata";
        when(samlSSOServiceProviderManager.addServiceProvider(any(SAMLSSOServiceProviderDO.class), anyInt()))
                .thenReturn(true);
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn(issuer);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        Assert.assertNotNull(samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata));
    }

    @Test
    public void testUpdateRelyingPartyServiceProviderWithMetadata() throws Exception {

        String metadata = "metadata";
        mockStatic(SAMLSSOUtil.class);
        when(SAMLSSOUtil.buildSPDataJSONString(any())).thenReturn("spDataJSONString");
        when(SAMLSSOUtil.buildSPData(any())).thenReturn(Collections.emptyMap());
        when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                .thenReturn(true);
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn("issuer");
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        Assert.assertNotNull(samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "issuer"));

    }

    @Test(expectedExceptions = IdentityException.class)
    public void testUpdateRelyingPartyServiceProviderWithMetadata1() throws Exception {

        String metadata = "metadata";
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn("issuer");
        when(samlSSOServiceProviderManager.updateServiceProvider(samlssoServiceProvDO, "testUser", userRegistry.getTenantId()))
                .thenReturn(false);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "issuer");
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testUpdateRelyingPartyServiceProviderWithMetadata2(String issuer) throws Exception {

        String metadata = "metadata";
        when(samlSSOServiceProviderManager.updateServiceProvider(any(SAMLSSOServiceProviderDO.class), anyString(), anyInt()))
                .thenReturn(true);
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn(issuer);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        Assert.assertNotNull(samlssoConfigAdmin.updateRelyingPartyServiceProviderWithMetadata(metadata, "testUser"));
    }

    @Test
    public void testGetServiceProviders() throws Exception {

        mockStatic(UserRegistry.class);
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

}
