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

package org.wso2.carbon.identity.sso.saml.util;

import org.mockito.Mock;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Status;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockObjectFactory;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.IObjectFactory;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.DataProvider;
import org.testng.annotations.ObjectFactory;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.internal.FrameworkServiceComponent;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.builders.X509CredentialImpl;
import org.wso2.carbon.identity.sso.saml.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.extension.eidas.EidasExtensionProcessor;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.identity.sso.saml.session.SessionInfoData;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotEquals;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Unit test cases for SAMLSSOUtil.
 */
@PrepareForTest({IdentityProviderManager.class, IdentityUtil.class, IdentityApplicationManagementUtil.class,
        KeyStoreManager.class, IdentitySAMLSSOServiceComponentHolder.class, SSOServiceProviderConfigManager.class,
        IdentityTenantUtil.class, ServiceURLBuilder.class, IdentityConstants.class, FrameworkServiceComponent.class,
        KeystoreUtils.class})
@PowerMockIgnore({"javax.xml.*", "org.xml.*", "org.w3c.dom.*", "org.apache.xerces.*"})
public class SAMLSSOUtilTest extends PowerMockTestCase {

    private static final String SAMPLE_TENANTED_SAML_URL = "https://localhost:9443/t/wso2.com/samlsso";

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

    private SessionInfoData sessionInfoData;

    @Mock
    private SAMLSSOServiceProviderManager samlSSOServiceProviderManager;

    @Mock
    private IdentitySAMLSSOServiceComponentHolder identitySAMLSSOServiceComponentHolder;

    @Mock
    private SSOServiceProviderConfigManager ssoServiceProviderConfigManager;

    @Mock
    ServiceURL serviceURL;
    @Mock
    private ServiceURLBuilder serviceURLBuilder;

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @BeforeTest
    public void setUp() throws Exception {

        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    private void prepareForGetKeyStorePath() throws Exception {
        mockStatic(KeystoreUtils.class);
        when(KeystoreUtils.getKeyStoreFileLocation(TestConstants.WSO2_TENANT_DOMAIN)).thenReturn(TestConstants
                .WSO2_TENANT_DOMAIN.replace(".", "-") + TestUtils.getFilePath(TestConstants.KEY_STORE_NAME));
    }

    private void prepareForGetIssuer() throws Exception {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).
                thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID)).
                thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
        when(realmService.getTenantManager()).thenReturn(tenantManager);

        SAMLSSOUtil.setRealmService(realmService);

        prepareResidentIdP();
    }

    private void prepareForGetSPConfig() throws Exception {

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setIssuer(TestConstants.ISSUER_WITH_QUALIFIER);
        samlssoServiceProviderDO.setIssuerQualifier(TestConstants.ISSUER_QUALIFIER);
        samlssoServiceProviderDO.setIdpEntityIDAlias(TestConstants.IDP_ENTITY_ID_ALIAS);

        when(samlSSOServiceProviderManager.getServiceProvider(anyString(), anyInt()))
                .thenReturn(samlssoServiceProviderDO);
        mockStatic(IdentitySAMLSSOServiceComponentHolder.class);
        when(IdentitySAMLSSOServiceComponentHolder.getInstance())
                .thenReturn(identitySAMLSSOServiceComponentHolder);
        when(identitySAMLSSOServiceComponentHolder.getSAMLSSOServiceProviderManager())
                .thenReturn(samlSSOServiceProviderManager);
        when(samlSSOServiceProviderManager.isServiceProviderExists(anyString(), anyInt())).thenReturn(true);

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        when(ssoServiceProviderConfigManager.getServiceProvider(TestConstants.ISSUER_WITH_QUALIFIER)).thenReturn(samlssoServiceProviderDO);
    }

    private void prepareServiceURLBuilder() throws URLBuilderException {

        mockStatic(ServiceURLBuilder.class);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addFragmentParameter(any(), any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addParameter(any(), any())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
    }

    private void setTenantQualifiedUrlMode() {

        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(true);
    }

    private void prepareResidentIdP() throws IdentityProviderManagementException {

        mockStatic(IdentityProviderManager.class);
        when(IdentityProviderManager.getInstance()).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);

        Property property = new Property();
        property.setName(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID);
        property.setValue(TestConstants.LOACALHOST_DOMAIN);
        Property[] properties = {property};

        when(federatedAuthenticatorConfig.getProperties()).thenReturn(properties);
        when(federatedAuthenticatorConfig.getName()).thenReturn(
                IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        FederatedAuthenticatorConfig[] fedAuthConfs = {federatedAuthenticatorConfig};
        when(identityProvider.getFederatedAuthenticatorConfigs()).thenReturn(fedAuthConfs);
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
    public void testGetDestinationFromServerURLBuilder() throws Exception {

        prepareResidentIdP();
        prepareServiceURLBuilder();

        when(serviceURL.getAbsolutePublicURL()).thenReturn(TestConstants.SAMPLE_SERVER_URL);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 1, "Expected to have one SAML destination url");
        assertEquals(destinationFromTenantDomain.get(0), TestConstants.SAMPLE_SERVER_URL, "Expected default built " +
                "SAML destination URL: " + TestConstants.SAMPLE_SERVER_URL);
    }

    @Test
    public void testGetDestinationFromServerURLBuilderAtTenantedURLMode() throws Exception {

        prepareResidentIdP();
        prepareServiceURLBuilder();
        setTenantQualifiedUrlMode();

        when(serviceURL.getAbsolutePublicURL()).thenReturn(TestConstants.SAMPLE_SERVER_URL);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 1, "Expected to have one SAML destination url");
        assertEquals(destinationFromTenantDomain.get(0), TestConstants.SAMPLE_SERVER_URL, "Expected default built " +
                "SAML destination URL: " + TestConstants.SAMPLE_SERVER_URL);
    }

    @Test
    public void testGetDestinationFromFile() throws Exception {

        prepareResidentIdP();
        prepareServiceURLBuilder();

        mockStatic(IdentityUtil.class);
        mockStatic(IdentityConstants.class);
        when(IdentityUtil.getProperty(IdentityConstants.ServerConfig.SSO_IDP_URL)).thenReturn(TestConstants
                .SAMPLE_SERVER_URL);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 1, "Expected to have one SAML destination url");
        assertEquals(destinationFromTenantDomain.get(0), TestConstants.SAMPLE_SERVER_URL, "Expected " +
                "SAML destination URL configured in file: " + TestConstants.SAMPLE_SERVER_URL);
    }

    @Test
    public void testGetDestinationFromFileInTenantedURLMode() throws Exception {

        prepareResidentIdP();
        prepareServiceURLBuilder();
        setTenantQualifiedUrlMode();

        mockStatic(IdentityUtil.class);
        mockStatic(IdentityConstants.class);
        when(IdentityUtil.getProperty(IdentityConstants.ServerConfig.SSO_IDP_URL)).thenReturn(TestConstants
                .SAMPLE_SERVER_URL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn(SAMPLE_TENANTED_SAML_URL);
        List<String> destinationFromTenantDomain = SAMLSSOUtil.getDestinationFromTenantDomain(TestConstants
                .WSO2_TENANT_DOMAIN);
        assertEquals(destinationFromTenantDomain.size(), 1, "Expected to have one destination url");
        assertEquals(destinationFromTenantDomain.get(0), SAMPLE_TENANTED_SAML_URL, "Expected default built " +
                "SAML destination URL: " + SAMPLE_TENANTED_SAML_URL);
        assertNotEquals(destinationFromTenantDomain.get(0), TestConstants.SAMPLE_SERVER_URL, "Expected to not to " +
                "return SAML destination URL configured in file: " + TestConstants.SAMPLE_SERVER_URL);
    }

    @Test
    public void testGetDestinationFromPredefinedDestinationURLs() throws Exception {

        prepareResidentIdP();
        prepareServiceURLBuilder();

        List destinationUrls = new ArrayList();
        destinationUrls.add("https://url1");
        destinationUrls.add("https://url2");
        mockStatic(IdentityApplicationManagementUtil.class);
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
        mockStatic(FrameworkServiceComponent.class);
        when(FrameworkServiceComponent.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        when(tenantManager.getTenantId(anyString())).thenReturn(-1234);
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
        prepareForGetKeyStorePath();
        mockStatic(FrameworkServiceComponent.class);
        when(FrameworkServiceComponent.getRealmService()).thenReturn(realmService);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
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
        prepareForGetKeyStorePath();
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

    @Test
    public void testisSAMLNotOnOrAfterPeriodDefined() {
        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC),
                true, "Expected to return true for a numeric value.");
        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_ALPHA),
                false, "Expected to false false for a alphabetic value.");
        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_ZERO),
                false, "Expected to return false for a zero.");
        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_EMPTY),
                false, "Expected to return false for a empty string.");
        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_WHITE_SPACE),
                false, "Expected to return false for white space.");
    }

    @Test
    public void testGetSAMLSessionNotOnOrAfterPeriod() {
        assertEquals(SAMLSSOUtil.getSAMLSessionNotOnOrAfterPeriod(TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC),
                15 * 60, "Expected to return the default value defined in the constants.");
    }

    @Test(dataProvider = "remainingSessionParticipantsforSloData")
    public void testGetRemainingSessionParticipantsForSLO(String sessionIndex, String issuer, boolean isIdPInitSLO,
                                                          int expected) {

        initializeData();
        List<SAMLSSOServiceProviderDO> samlssoServiceProviderDOList = SAMLSSOUtil.getRemainingSessionParticipantsForSLO
                (sessionIndex, issuer, isIdPInitSLO, MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(samlssoServiceProviderDOList.size(), expected);

    }

    @DataProvider(name = "remainingSessionParticipantsforSloData")
    public Object[][] remainingSessionParticipantsforSloData() {

        return new Object[][]{
                {null, null, true, 0},
                {null, "issuer", false, 0},
                {"sessionIndex", null, false, 2},
                {"sessionIndex", "issuer1", false, 1},
                {"sessionIndex", "issuer1", true, 2}
        };
    }

    public void initializeData() {

        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityTenantUtil.getTenantId(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)).
                thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(IdentityTenantUtil.getTenantDomain(MultitenantConstants.SUPER_TENANT_ID)).
                thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO1 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO1.setIssuer("issuer1");
        samlssoServiceProviderDO1.setDoSingleLogout(true);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO2 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO2.setIssuer("issuer2");
        samlssoServiceProviderDO2.setDoSingleLogout(true);

        SAMLSSOServiceProviderDO samlssoServiceProviderDO3 = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO3.setIssuer("issuer3");
        samlssoServiceProviderDO3.setDoSingleLogout(false);

        sessionInfoData = new SessionInfoData();
        sessionInfoData.addServiceProvider("issuer1", samlssoServiceProviderDO1, null);
        sessionInfoData.addServiceProvider("issuer2", samlssoServiceProviderDO2, null);
        sessionInfoData.addServiceProvider("issuer3", samlssoServiceProviderDO3, null);

        SSOSessionPersistenceManager.addSessionIndexToCache("samlssoTokenId", "sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        SSOSessionPersistenceManager.addSessionInfoDataToCache("sessionIndex", sessionInfoData,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
    }

    @Test
    public void testGetSessionInfoData() {

        initializeData();
        assertEquals(SAMLSSOUtil.getSessionInfoData("sessionIndex",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), sessionInfoData);
        assertNotEquals(SAMLSSOUtil.getSessionInfoData("sessionIndex1",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), sessionInfoData);
    }

    @Test
    public void testGetSessionIndex() {

        initializeData();
        assertEquals(SAMLSSOUtil.getSessionIndex("samlssoTokenId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), "sessionIndex");
        assertNull(SAMLSSOUtil.getSessionIndex("sessionId",
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME), "Session Index is null.");
    }


    @Test
    public void testGetIssuerWhenEntityIDAliasEnabled() throws Exception {

        SAMLSSOUtil.setIssuerWithQualifierInThreadLocal(TestConstants.ISSUER_WITH_QUALIFIER);
        prepareForGetIssuer();
        prepareForGetSPConfig();
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        Issuer issuer = SAMLSSOUtil.getIssuerFromTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        assertEquals(issuer.getValue(), TestConstants.IDP_ENTITY_ID_ALIAS, "Issuer for specific service provider.");
    }

    @DataProvider(name = "issuerProvider")
    public Object[][] getIssuerData() {

        return new Object[][]{
                {"travelocity.com", null, "travelocity.com"},
                {"travelocity.com", "", "travelocity.com"},
                {"travelocity.com", "wso2.com", "travelocity.com:urn:sp:qualifier:wso2.com"},
        };
    }

    @Test(dataProvider = "issuerProvider")
    public void testGetIssuerWithQualifier(String issuer, String qualifier, String expected) throws Exception {

        assertEquals(SAMLSSOUtil.getIssuerWithQualifier(issuer, qualifier), expected);
    }

    @DataProvider(name = "issuerWithQualifierProvider")
    public Object[][] getIssuerWithQualifierData() {

        return new Object[][]{
                {"travelocity.com", "travelocity.com"},
                {"travelocity.com:urn:sp:qualifier:wso2.com", "travelocity.com"},
        };
    }

    @Test(dataProvider = "issuerWithQualifierProvider")
    public void testGetIssuerWithoutQualifier(String issuerWithQualifier, String expected) throws Exception {

        assertEquals(SAMLSSOUtil.getIssuerWithoutQualifier(issuerWithQualifier), expected);
    }
}
