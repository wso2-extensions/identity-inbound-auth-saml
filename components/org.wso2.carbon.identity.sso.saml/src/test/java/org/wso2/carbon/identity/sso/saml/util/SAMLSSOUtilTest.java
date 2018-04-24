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
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Status;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.extension.eidas.EidasExtensionProcessor;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Matchers.*;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.*;

/**
 * Unit test cases for SAMLSSOUtil.
 */
@PrepareForTest({IdentityProviderManager.class, IdentityUtil.class, IdentityApplicationManagementUtil.class,
        KeyStoreManager.class})
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
    private KeyStoreManager keyStoreManager;

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

        assertEquals(SAMLSSOUtil.decodeForPost(TestConstants.ENCODED_POST_LOGOUT_REQUEST),
                TestConstants.DECODED_POST_LOGOUT_REQUEST,
                "Decoded value of encoded Post Authentication Request is not as expected.");
    }

    @DataProvider(name = "testCompressResponse")
    public static Object[][] compressStrings() {

        return new Object[][]{
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

    @Test
    public void testSetTenantDomain() throws Exception {

        SAMLSSOUtil.setUserTenantDomain(TestConstants.WSO2_TENANT_DOMAIN);
        assertEquals(SAMLSSOUtil.getUserTenantDomain(), TestConstants.WSO2_TENANT_DOMAIN, "Didn't get back the tenant" +
                " domain which was set to");
    }

    @Test
    public void testRemoveTenantDomain() throws Exception {

        SAMLSSOUtil.setUserTenantDomain(TestConstants.WSO2_TENANT_DOMAIN);
        SAMLSSOUtil.removeUserTenantDomainThreaLocal();
        assertNull(SAMLSSOUtil.getUserTenantDomain(), "Tenant domain was removed. But still exists in the thread " +
                "local");
    }

    @Test
    public void testGetDestinationForServerURL() throws Exception {

        prepareForGetIssuer();
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(TestConstants
                .SAMPLE_SERVER_URL);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 1, "Expected to have one destination url");
        assertEquals(destinationFromTenantDomain.get(0), TestConstants.SAMPLE_SERVER_URL, "Server URL is not present " +
                "in destination URLs");
    }

    @Test
    public void testGetDestinationForTenant() throws Exception {

        prepareForGetIssuer();
        List destinationUrls = new ArrayList();
        destinationUrls.add("https://url1");
        destinationUrls.add("https://url2");
        mockStatic(IdentityUtil.class);
        mockStatic(IdentityApplicationManagementUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean())).thenReturn(TestConstants
                .SAMPLE_SERVER_URL);
        when(IdentityApplicationManagementUtil.getPropertyValuesForNameStartsWith(any(FederatedAuthenticatorConfig[]
                .class), eq(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME), eq(IdentityApplicationConstants
                .Authenticator.SAML2SSO.DESTINATION_URL_PREFIX))).thenReturn(destinationUrls);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 2, "Expected to have one destination url");
        assertTrue(destinationFromTenantDomain.contains("https://url1"), "Destination URL 1 does not contain in the " +
                "returned list");
        assertTrue(destinationFromTenantDomain.contains("https://url2"), "Destination URL 2 does not contain in the " +
                "returned list");
        assertFalse(destinationFromTenantDomain.contains(TestConstants.SAMPLE_SERVER_URL), "Server URL contains in " +
                "the returned list");
    }

    @Test(expectedExceptions = IdentityException.class)
    public void testGetDestinationException() throws Exception {

        prepareForGetIssuer();
        when(identityProviderManager.getInstance().getResidentIdP(anyString())).thenThrow
                (IdentityProviderManagementException.class);
        SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants.WSO2_TENANT_DOMAIN);
    }

    @Test
    public void testGetX509CredentialImplForSuperTenant() throws Exception {

        prepareForGetIssuer();
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(eq(-1234))).thenReturn(keyStoreManager);
        when(keyStoreManager.getPrimaryKeyStore()).thenReturn(TestUtils.loadKeyStoreFromFileSystem(TestUtils
                .getFilePath("wso2carbon.jks"), "wso2carbon", "JKS"));
        X509CredentialImpl x509Credential = SAMLSSOUtil.getX509CredentialImplForTenant("carbon.super", "wso2carbon");
        assertNotNull(x509Credential.getPublicKey(), "public key is missing");
    }

    @Test
    public void testGetX509CredentialImplForTenant() throws Exception {

        prepareForGetIssuer();
        when(tenantManager.getTenantId(anyString())).thenReturn(1);
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(eq(1))).thenReturn(keyStoreManager);
        when(keyStoreManager.getKeyStore(eq(SAMLSSOUtil.generateKSNameFromDomainName(TestConstants.WSO2_TENANT_DOMAIN)))).thenReturn
                (TestUtils.loadKeyStoreFromFileSystem(TestUtils
                        .getFilePath(TestConstants.KEY_STORE_NAME), TestConstants.WSO2_CARBON, "JKS"));
        X509CredentialImpl x509Credential = SAMLSSOUtil.getX509CredentialImplForTenant(TestConstants
                .WSO2_TENANT_DOMAIN, TestConstants.WSO2_CARBON);
        assertNotNull(x509Credential.getPublicKey(), "public key is missing for tenant");
    }

    @Test(expectedExceptions = IdentitySAML2SSOException.class)
    public void testGetX509CredentialImplException() throws Exception {

        prepareForGetIssuer();
        when(tenantManager.getTenantId(anyString())).thenReturn(1);
        mockStatic(KeyStoreManager.class);
        when(KeyStoreManager.getInstance(eq(1))).thenReturn(keyStoreManager);
        when(keyStoreManager.getKeyStore(eq(SAMLSSOUtil.generateKSNameFromDomainName(TestConstants.WSO2_TENANT_DOMAIN)))).thenReturn
                (null);
        X509CredentialImpl x509Credential = SAMLSSOUtil.getX509CredentialImplForTenant(TestConstants
                .WSO2_TENANT_DOMAIN, TestConstants.WSO2_CARBON);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetX509CredentialImplEmptyTenant() throws Exception {

        SAMLSSOUtil.getX509CredentialImplForTenant(null, TestConstants.WSO2_CARBON);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void testGetX509CredentialImplEmptyAlias() throws Exception {

        SAMLSSOUtil.getX509CredentialImplForTenant(TestConstants.WSO2_TENANT_DOMAIN, null);
    }

    @Test(expectedExceptions = IdentitySAML2SSOException.class)
    public void testGetX509CredentialImplForInvalidTenant() throws Exception {

        prepareForGetIssuer();
        when(tenantManager.getTenantId(anyString())).thenThrow(UserStoreException.class);
        SAMLSSOUtil.getX509CredentialImplForTenant(TestConstants
                .WSO2_TENANT_DOMAIN, TestConstants.WSO2_CARBON);
    }

    @Test
    public void testAddExtensionProcessors() {
        SAMLSSOUtil.addExtensionProcessors(new EidasExtensionProcessor());
        assertEquals(SAMLSSOUtil.getExtensionProcessors().size(), 1, "Extension processor is not " +
                "added to the extension processor list.");
    }

    @Test
    public void testRemoveExtensionProcessors() {
        SAMLSSOUtil.removeExtensionProcessors(new EidasExtensionProcessor());
        assertEquals(SAMLSSOUtil.getExtensionProcessors().size(), 0, "Extension processor is not " +
                "removed from the extension processor list.");
    }

    @Test
    public void testBuildResponseStatus() {
        String statusCode = "500";
        String statusMsg = "Internal Server Error";
        Status status = SAMLSSOUtil.buildResponseStatus(statusCode, statusMsg);
        assertEquals(status.getStatusCode().getValue(), statusCode, "Status code is not properly set in the Status " +
                "object.");
        assertEquals(status.getStatusMessage().getMessage(), statusMsg, "Status Message is not properly set in " +
                "the Status object.");
    }
}
