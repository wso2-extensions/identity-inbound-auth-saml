/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
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

import org.mockito.InjectMocks;
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
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.sp.metadata.saml2.util.Parser;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2ClientException;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.session.UserRegistry;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.MockitoAnnotations.initMocks;
import static org.powermock.api.mockito.PowerMockito.*;

@PrepareForTest({IdentityPersistenceManager.class, SSOServiceProviderConfigManager.class,
        SAMLSSOServiceProviderDO.class, Parser.class, UserRegistry.class, SAMLSSOConfigAdmin.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.apache.xerces.*", "org.w3c.dom.*"})
public class SAMLSSOConfigAdminTest extends PowerMockTestCase {

    @InjectMocks
    private SAMLSSOConfigAdmin samlssoConfigAdmin;

    @Mock
    UserRegistry userRegistry;

    @Mock
    private IdentityPersistenceManager identityPersistenceManager;

    @Mock
    SAMLSSOServiceProviderDO samlssoServiceProvDO;

    @Mock
    SSOServiceProviderConfigManager ssoServiceProviderConfigManager;

    @Mock
    Parser parser;

    @BeforeMethod
    public void setUp() throws Exception {

        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        samlssoConfigAdmin = new SAMLSSOConfigAdmin(userRegistry);
        mockStatic(IdentityPersistenceManager.class);
        when(IdentityPersistenceManager.getPersistanceManager()).thenReturn(identityPersistenceManager);
        mockStatic(SAMLSSOServiceProviderDO.class);
    }

    @AfterMethod
    public void tearDown() throws Exception {

    }

    @Test
    public void testAddRelyingPartyServiceProvider() throws IdentityException {

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        when(identityPersistenceManager.addServiceProvider(any(Registry.class), any(SAMLSSOServiceProviderDO.class)))
                .thenReturn(true);
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer("testUser");

        Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), true);
        samlssoServiceProvDO = new SAMLSSOServiceProviderDO();
        when(ssoServiceProviderConfigManager.getServiceProvider("testUser")).thenReturn(samlssoServiceProvDO);
        Assert.assertEquals(samlssoConfigAdmin.addRelyingPartyServiceProvider(samlssoServiceProviderDTO), false);
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
        when(identityPersistenceManager.addServiceProvider(any(Registry.class), any(SAMLSSOServiceProviderDO.class))).
                thenReturn(true);
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
        when(identityPersistenceManager.addServiceProvider(userRegistry, samlssoServiceProvDO)).thenReturn(false);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata);
    }

    @Test(expectedExceptions = IdentityException.class, dataProvider = "dataProviders")
    public void testUploadRelyingPartyServiceProvider2(String issuer) throws Exception {

        String metadata = "metadata";
        when(identityPersistenceManager.addServiceProvider(any(Registry.class), any(SAMLSSOServiceProviderDO.class)))
                .thenReturn(true);
        whenNew(SAMLSSOServiceProviderDO.class).withNoArguments().thenReturn(samlssoServiceProvDO);
        when(samlssoServiceProvDO.getIssuer()).thenReturn(issuer);
        whenNew(Parser.class).withArguments(any(UserRegistry.class)).thenReturn(parser);
        when(parser.parse(anyString(), any(SAMLSSOServiceProviderDO.class))).thenReturn(samlssoServiceProvDO);
        Assert.assertNotNull(samlssoConfigAdmin.uploadRelyingPartyServiceProvider(metadata));
    }

    @Test
    public void testGetServiceProviders() throws Exception {

        mockStatic(UserRegistry.class);
        SAMLSSOServiceProviderDO[] serviceProvidersList = new SAMLSSOServiceProviderDO[3];
        when(userRegistry.getTenantId()).thenReturn(0);
        when(identityPersistenceManager.getServiceProviders(any(UserRegistry.class))).thenReturn(serviceProvidersList);

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