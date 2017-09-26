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

package org.wso2.carbon.identity.sso.saml.util;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml2.core.Issuer;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;

import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

/**
 * Unit test cases for SAMLSSOUtil.
 */
@PrepareForTest(IdentityProviderManager.class)
public class SAMLSSOUtilTest extends PowerMockTestCase {

    @Mock
    private RealmService realmService;

    @Mock
    private TenantManager tenantManager;

    @Mock
    private IdentityProviderManager identityProviderManager;

    @Mock
    private IdentityProvider identityProvider;

    @Mock
    private FederatedAuthenticatorConfig federatedAuthenticatorConfig;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    private void prepareForGetIssuer() throws Exception {

        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(realmService.getTenantManager()).thenReturn(tenantManager);

        SAMLSSOUtil.setRealmService(realmService);

        Property property = new Property();
        property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
        property.setValue(TestConstants.LOACALHOST_DOMAIN);
        Property[] properties = {property};
        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(federatedAuthenticatorConfig.getName()).thenReturn(
                IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        FederatedAuthenticatorConfig[] fedAuthConfs = {federatedAuthenticatorConfig};
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(fedAuthConfs);

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
    }

    @Test
    public void testGetIssuer() throws Exception {

        prepareForGetIssuer();
        Issuer issuer = SAMLSSOUtil.getIssuer();
        assertEquals(issuer.getValue(), TestConstants.LOACALHOST_DOMAIN);
        assertEquals(issuer.getFormat(), SAMLSSOConstants.NAME_ID_POLICY_ENTITY,
                "Issuer format should always be SAML2 spec compatible.");
    }

    @Test
    public void testGetIssuerFromTenantDomain() throws Exception {

        prepareForGetIssuer();
        Issuer issuer = SAMLSSOUtil.getIssuerFromTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(issuer.getValue(), TestConstants.LOACALHOST_DOMAIN, "Issuer for Super tenant domain.");
    }

    @Test
    public void testEncode() throws Exception {

        String encodedXml = SAMLSSOUtil.encode(TestConstants.AUTHN_FAILED_SAML_RESPONSE);
        assertFalse(encodedXml.isEmpty(), "Encoded xml should not be empty.");
        assertFalse(encodedXml.contains(" "), "Encoded xml should not contain spaces.");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testDecode() throws Exception {

        assertEquals(SAMLSSOUtil.decode(TestConstants.ENCODED_REDIRECT_AUTHN_REQUEST),
                TestConstants.DECODED_REDIRECT_AUTHN_REQUEST,
                "Decoded value of encoded Redirect Authentication Request is not as expected.");
        SAMLSSOUtil.decode(TestConstants.GENERAL_STRING);
    }

    @Test
    public void testDecodeForPost() throws Exception {

        assertEquals(SAMLSSOUtil.decodeForPost(TestConstants.ENCODED_POST_AUTHN_REQUEST),
                TestConstants.DECODED_POST_AUTHN_REQUEST,
                "Decoded value of encoded Post Authentication Request is not as expected.");
    }

    @DataProvider(name = "testCompressResponse")
    public static Object[][] compressStrings() {

        return new Object[][] {
                {TestConstants.AUTHN_FAILED_SAML_RESPONSE,
                        "Compressed Authentication Failed SAML response should not be empty."},
                {TestConstants.GENERAL_STRING,
                        "Compressed general string should not be empty."}
        };
    }

    @Test(dataProvider = "testCompressResponse")
    public void testCompressResponse(String stringToCompress, String message) throws Exception {

        assertFalse(SAMLSSOUtil.compressResponse(stringToCompress).isEmpty(), message);
    }

    @Test
    public void testIsSaaSApplication() throws Exception {

        assertFalse(SAMLSSOUtil.isSaaSApplication(), "Default value of isSaaSApplication is true.");
        SAMLSSOUtil.setIsSaaSApplication(false);
        assertFalse(SAMLSSOUtil.isSaaSApplication(), "isSaaSApplication is set to false.");
        SAMLSSOUtil.setIsSaaSApplication(true);
        assertTrue(SAMLSSOUtil.isSaaSApplication(), "isSaaSApplication is set to true.");
    }
}
