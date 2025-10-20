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

import org.apache.axis2.transport.http.HTTPConstants;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.security.x509.X509Credential;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.common.testng.WithCarbonHome;
import org.wso2.carbon.identity.core.SAMLSSOServiceProviderManager;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.saml.common.util.SAMLInitializer;
import org.wso2.carbon.identity.sso.saml.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.SAMLTestRequestBuilder;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

import static org.wso2.carbon.identity.core.util.IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;
import static org.wso2.carbon.identity.sso.saml.TestConstants.SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC;

/**
 * Tests Assertion building functionality.
 */
@WithCarbonHome
public class AssertionBuildingTest {

    @Mock
    private RealmService realmService;

    @Mock
    private IdentitySAMLSSOServiceComponentHolder identitySAMLSSOServiceComponentHolder;

    @Mock
    private SAMLSSOServiceProviderManager samlssoServiceProviderManager;

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

    @Mock
    SSOServiceProviderConfigManager ssoServiceProviderConfigManager;

    @Mock
    private X509Credential x509Credential;

    private MockedStatic<FrameworkUtils> frameworkUtilsStatic;
    private AutoCloseable openMocks;

    @BeforeMethod
    public void setUpBeforeMethod() throws Exception {

        openMocks = MockitoAnnotations.openMocks(this);
        frameworkUtilsStatic = Mockito.mockStatic(FrameworkUtils.class);
        frameworkUtilsStatic.when(FrameworkUtils::getMultiAttributeSeparator)
                .thenReturn(MULTI_ATTRIBUTE_SEPARATOR_DEFAULT);
    }

    @AfterMethod
    public void tearDown() {
        if (frameworkUtilsStatic != null) {
            frameworkUtilsStatic.close();
            frameworkUtilsStatic = null;
        }
        if (openMocks != null) {
            try { openMocks.close(); } catch (Exception ignore) {}
        }
        SAMLSSOUtil.setSPInitSSOAuthnRequestValidator(null);
        Mockito.framework().clearInlineMocks();
    }

    @Test
    public void testBuildAssertion() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilStatic = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityProviderManager> idPManagerStatic = mockStatic(IdentityProviderManager.class);
             MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic
                     = mockStatic(SSOServiceProviderConfigManager.class)) {
            Assertion assertion = buildAssertion(identityUtilStatic, idPManagerStatic, sSOSPConfigManagerStatic);
            assertEquals(assertion.getSubject().getNameID().getValue(), TestConstants.TEST_USER_NAME, 
                    "Correct subject is not set to assertion");
            assertEquals(assertion.getAttributeStatements().size(), 1, 
                    "Expected to have one attribute statement");
            assertEquals(assertion.getAttributeStatements().get(0).getAttributes().size(), 2, 
                    "Expected to have two attributes");

            Map map = new HashMap();
            map.put(assertion.getAttributeStatements().get(0).getAttributes().get(0).getName(), assertion
                    .getAttributeStatements().get(0).getAttributes().get(0).getName());
            map.put(assertion.getAttributeStatements().get(0).getAttributes().get(1).getName(), assertion
                    .getAttributeStatements().get(0).getAttributes().get(1).getName());

            assertTrue(map.containsKey(TestConstants.CLAIM_URI1));
            assertTrue(map.containsKey(TestConstants.CLAIM_URI2));
        }
    }

    @Test
    public void testSetSignature() throws Exception {

        TestUtils.prepareCredentials(x509Credential);
        try (MockedStatic<IdentityUtil> identityUtilStatic = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityProviderManager> idPManagerStatic = mockStatic(IdentityProviderManager.class);
             MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic
                     = mockStatic(SSOServiceProviderConfigManager.class)) {
            Assertion assertion = buildAssertion(identityUtilStatic, idPManagerStatic, sSOSPConfigManagerStatic);
            assertNull(assertion.getSignature(), "Initially a signature was present before signing");
            
            identityUtilStatic.when(() -> IdentityUtil.getProperty(anyString())).thenReturn(
                    "org.wso2.carbon.identity.sso.saml.builders.signature.DefaultSSOSigner");
            Assertion resultAssertion = SAMLSSOUtil.setSignature(assertion, TestConstants.RSA_SHA1_SIG_ALGO,
                    TestConstants.SHA1_DIGEST_ALGO, x509Credential);
            assertNotNull(resultAssertion.getSignature(), "Signature not present in assertion");
            assertTrue(TestConstants.RSA_SHA1_SIG_ALGO.equalsIgnoreCase(resultAssertion.getSignature()
                    .getSignatureAlgorithm()), "Signature algorithm is not the one which was set");
        }
    }

    @Test
    public void testGetAttributes() throws Exception {

        try (MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic
                     = mockStatic(SSOServiceProviderConfigManager.class)) {
            prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.LOACALHOST_DOMAIN,
                    TestConstants.LOACALHOST_DOMAIN, sSOSPConfigManagerStatic);
            Map<String, String> inputAttributes = new HashMap<>();
            inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
            inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
            Map<String, String> attributes = SAMLSSOUtil.getAttributes(TestUtils.buildAuthnReqDTO(inputAttributes,
                    TestConstants.SAMPLE_NAME_ID_FORMAT, TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME));
            assertTrue(attributes.containsKey(TestConstants.CLAIM_URI1), "Claim1 is not present in user attributes");
            assertTrue(attributes.containsKey(TestConstants.CLAIM_URI2), "Claim2 is not present in user attributes");
            assertTrue(TestConstants.CLAIM_VALUE1.equalsIgnoreCase(attributes.get(TestConstants.CLAIM_URI1)), "Received " +
                    "Claim1 value is incorrect");
            assertTrue(TestConstants.CLAIM_VALUE2.equalsIgnoreCase(attributes.get(TestConstants.CLAIM_URI2)), "Received " +
                    "Claim2 value is incorrect");
        }
    }

    @Test
    public void validateACS() throws Exception {

        try (MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic
                     = mockStatic(SSOServiceProviderConfigManager.class)) {
            prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER,
                    TestConstants.TRAVELOCITY_ISSUER, sSOSPConfigManagerStatic);
            TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                    .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
            assertTrue(isACSValied, "Expected to ACS to be validated. But failed");
        }
    }

    @Test
    public void validateACSWithoutIssuer() throws Exception {

        try (MockedStatic<IdentitySAMLSSOServiceComponentHolder> iSAMLSSOSCHolderStatic =
                     mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            prepareIdentityPersistentManager(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER,
                    Collections.emptyList(), iSAMLSSOSCHolderStatic);
            boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                    .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
            assertFalse(isACSValied, "Expected to ACS to be validated. But failed");
        }
    }

    @Test
    public void validateACSWithACSInSP() throws Exception {

        try (MockedStatic<IdentitySAMLSSOServiceComponentHolder> iSAMLSSOSCHolderStatic =
                     mockStatic(IdentitySAMLSSOServiceComponentHolder.class)) {
            List<String> acs = new ArrayList();
            acs.add(TestConstants.ACS_URL);
            prepareIdentityPersistentManager(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER
                    , acs, iSAMLSSOSCHolderStatic);
            boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                    .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
            assertTrue(isACSValied, "No ACS configured in SAML SP. Hence expecting false");
        }
    }

    @DataProvider(name = "getSPInitSSOAuthnRequestValidator")
    public Object[][] getSSOAuthnValidatorClasses() {
        String signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
        return new Object[][]{
                {null, "Expected SP init SSO Authn Request validator not to be null"},
                {"org.wso2.carbon.identity.sso.saml.validators.SPInitSSOAuthnRequestValidator", "Expected SP init SSO" +
                        " Authn Request validator not to be null"},
        };
    }

    @Test(dataProvider = "getSPInitSSOAuthnRequestValidator")
    public void getSPInitSSOAuthnRequestValidator(String spInitSSOAuthnReqValidator, String message) throws Exception {

        SAMLSSOUtil.setSPInitSSOAuthnRequestValidator(spInitSSOAuthnReqValidator);
        SAMLInitializer.doBootstrap();
        AuthnRequest authnRequest = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false,
                false, HTTPConstants.HTTP_METHOD_GET, TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        SSOAuthnRequestValidator spInitSSOAuthnRequestValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator(
                authnRequest);
        assertNotNull(spInitSSOAuthnRequestValidator, message);
    }

    @Test
    public void getSPInitAuthReqValidatorWithInvalidClass() throws Exception {

        SAMLSSOUtil.setSPInitSSOAuthnRequestValidator("org.wso2.carbon.identity.sso.saml.validators" +
                ".NonExistingClass");
        SAMLInitializer.doBootstrap();
        AuthnRequest authnRequest = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                HTTPConstants.HTTP_METHOD_GET, TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        SSOAuthnRequestValidator spInitSSOAuthnRequestValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator
                (authnRequest);
        assertNull(spInitSSOAuthnRequestValidator, "Expected SP init SSO Authn Request validator to be null");
    }

    @Test
    public void getSPInitValidatorWithNonExistingClass() throws Exception {

        SAMLSSOUtil.setSPInitSSOAuthnRequestValidator("org.wso2.carbon.identity.sso.saml.validators.NonExistingClass");
        SAMLInitializer.doBootstrap();
        AuthnRequest authnRequest = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                "GET", TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        SSOAuthnRequestValidator spInitSSOAuthnRequestValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator
                (authnRequest);
        assertNull(spInitSSOAuthnRequestValidator, "Expected SP init SSO Authn Request validator to be null");
    }

    @Test
    public void testBuildAssertionWithSessionNotOnOrAfter() throws Exception {

        try (MockedStatic<IdentityUtil> identityUtilStatic = Mockito.mockStatic(IdentityUtil.class);
             MockedStatic<IdentityProviderManager> idPManagerStatic = mockStatic(IdentityProviderManager.class);
             MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic
                     = mockStatic(SSOServiceProviderConfigManager.class)) {
            Assertion assertion = buildAssertionWithSessionNotOnOrAfter(identityUtilStatic, idPManagerStatic, 
                    sSOSPConfigManagerStatic);
            List<AuthnStatement> authStatements = assertion.getAuthnStatements();
            DateTimeZone utcTimeZone = DateTimeZone.UTC;
            DateTime sessionNotOnOrAfterTestValue = new DateTime(authStatements.get(0).getAuthnInstant().getMillis() +
                    TimeUnit.SECONDS.toMillis(
                            (long) Integer.parseInt(SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC.trim()) * 60), 
                    utcTimeZone);
            assertEquals(assertion.getAuthnStatements().get(0).getSessionNotOnOrAfter(), sessionNotOnOrAfterTestValue,
                    "Expected value for the SessionNotOnOrAfter is different.");
        }
    }

    private void prepareForGetIssuer(MockedStatic<IdentityProviderManager> idPManagerStatic) throws Exception {

        when(tenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
        when(tenantManager.getDomain(anyInt())).thenReturn(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        IdentityTenantUtil.setRealmService(realmService);

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
        
        idPManagerStatic.when(IdentityProviderManager::getInstance).thenReturn(identityProviderManager);
        when(identityProviderManager.getResidentIdP(anyString())).thenReturn(identityProvider);
    }

    private void prepareForUserAttributes(String attrConsumerIndex, String issuer, String spName, 
                                          MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic) {
        
        sSOSPConfigManagerStatic.when(SSOServiceProviderConfigManager::getInstance)
                .thenReturn(ssoServiceProviderConfigManager);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setAttributeConsumingServiceIndex(attrConsumerIndex);
        samlssoServiceProviderDO.setEnableAttributesByDefault(true);
        samlssoServiceProviderDO.setIssuer(issuer);
        ssoServiceProviderConfigManager.addServiceProvider(issuer, samlssoServiceProviderDO);
        when(ssoServiceProviderConfigManager.getServiceProvider(spName)).thenReturn(samlssoServiceProviderDO);
    }


    private Assertion buildAssertion(MockedStatic<IdentityUtil> identityUtilStatic, 
                                     MockedStatic<IdentityProviderManager> idPManagerStatic,
                                     MockedStatic<SSOServiceProviderConfigManager> sSOSPConfigManagerStatic) 
            throws Exception {

        prepareForGetIssuer(idPManagerStatic);
        identityUtilStatic.when(() -> IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn(TestConstants.SAMPLE_SERVER_URL);
        prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.LOACALHOST_DOMAIN,
                TestConstants.LOACALHOST_DOMAIN, sSOSPConfigManagerStatic);
        Map<String, String> inputAttributes = new HashMap<>();
        inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
        inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
        SAMLSSOAuthnReqDTO authnReqDTO = TestUtils.buildAuthnReqDTO(inputAttributes, TestConstants.SAMPLE_NAME_ID_FORMAT,
                TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME);

        authnReqDTO.setNameIDFormat(TestConstants.SAMPLE_NAME_ID_FORMAT);
        authnReqDTO.setIssuer(TestConstants.LOACALHOST_DOMAIN);

        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(SAMLSSOUtil.getIssuer());
        response.setID(SAMLSSOUtil.createID());
        if (!authnReqDTO.isIdPInitSSOEnabled()) {
            response.setInResponseTo(authnReqDTO.getId());
        }
        response.setDestination(authnReqDTO.getAssertionConsumerURL());
        response.setStatus(SAMLSSOUtil.buildResponseStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
        response.setVersion(SAMLVersion.VERSION_20);
        DateTime issueInstant = new DateTime();
        response.setIssueInstant(issueInstant);

        Assertion assertion = SAMLSSOUtil.buildSAMLAssertion(authnReqDTO, new DateTime(00000000L), TestConstants
                .SESSION_ID);
        return assertion;
    }

    private Assertion buildAssertionWithSessionNotOnOrAfter(MockedStatic<IdentityUtil> identityUtilStatic, 
                                                            MockedStatic<IdentityProviderManager> idPManagerStatic,
                                                            MockedStatic<SSOServiceProviderConfigManager> 
                                                                    sSOSPConfigManagerStatic) 
            throws Exception {

        Assertion assertion = buildAssertion(identityUtilStatic, idPManagerStatic, sSOSPConfigManagerStatic);
        List<AuthnStatement> authStatements = assertion.getAuthnStatements();
        if (authStatements != null && authStatements.size() > 0) {
            // There can be only one authentication stmt inside the SAML assertion of generating in the test
            AuthnStatement authStmt = authStatements.get(0);
            String sessionNotOnOrAfterValue = SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC;
            if (SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(sessionNotOnOrAfterValue)) {
                DateTime sessionNotOnOrAfter = new DateTime(authStmt.getAuthnInstant().getMillis() +
                        TimeUnit.SECONDS.toMillis((long) SAMLSSOUtil.getSAMLSessionNotOnOrAfterPeriod(sessionNotOnOrAfterValue)));
                authStmt.setSessionNotOnOrAfter(sessionNotOnOrAfter);
            }
        }
        return assertion;
    }

    private void prepareIdentityPersistentManager(String attrConsumerIndex, String issuer, List acsList, 
                                                  MockedStatic<IdentitySAMLSSOServiceComponentHolder> 
                                                          iSAMLSSOSCHolderStatic) throws IdentityException {

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setAttributeConsumingServiceIndex(attrConsumerIndex);
        samlssoServiceProviderDO.setEnableAttributesByDefault(true);
        samlssoServiceProviderDO.setIssuer(issuer);
        samlssoServiceProviderDO.setAssertionConsumerUrls(acsList);
        when(samlssoServiceProviderManager.getServiceProvider(eq(issuer), anyInt()))
                .thenReturn(samlssoServiceProviderDO);
        
        iSAMLSSOSCHolderStatic.when(IdentitySAMLSSOServiceComponentHolder::getInstance)
                .thenReturn(identitySAMLSSOServiceComponentHolder);
        when(identitySAMLSSOServiceComponentHolder.getSAMLSSOServiceProviderManager())
                .thenReturn(samlssoServiceProviderManager);
    }

    @Test
    public void testisSAMLNotOnOrAfterPeriodDefined() {

        assertEquals(SAMLSSOUtil.isSAMLNotOnOrAfterPeriodDefined(SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC),
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

        assertEquals(SAMLSSOUtil.getSAMLSessionNotOnOrAfterPeriod(SAML_SESSION_NOT_ON_OR_AFTER_PERIOD_NUMERIC),
                15 * 60, "Expected to return the default value defined in the constants.");
    }
}
