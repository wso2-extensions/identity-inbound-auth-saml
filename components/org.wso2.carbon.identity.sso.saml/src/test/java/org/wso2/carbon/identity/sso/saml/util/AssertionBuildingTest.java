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

import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.lang.StringUtils;
import org.joda.time.DateTime;
import org.mockito.Mock;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.security.x509.X509Credential;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
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
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.persistence.IdentityPersistenceManager;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.SAMLTestRequestBuilder;
import org.wso2.carbon.identity.sso.saml.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.TestConstants;
import org.wso2.carbon.identity.sso.saml.TestUtils;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;
import org.wso2.carbon.identity.sso.saml.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyString;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.powermock.api.mockito.PowerMockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertNull;
import static org.testng.Assert.assertTrue;

/**
 * Tests Assertion building functionality.
 */
@PowerMockIgnore({"javax.net.*"})
@PrepareForTest({IdentityUtil.class, IdentityTenantUtil.class, IdentityProviderManager.class,
        SSOServiceProviderConfigManager.class, IdentityPersistenceManager.class})

public class AssertionBuildingTest extends PowerMockTestCase {

    @ObjectFactory
    public IObjectFactory getObjectFactory() {
        return new PowerMockObjectFactory();
    }

    @Mock
    private RealmService realmService;

    @Mock
    private IdentityPersistenceManager identityPersistenceManager;

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

    @Test
    public void testBuildAssertion() throws Exception {

        Assertion assertion = buildAssertion();
        assertEquals(assertion.getSubject().getNameID().getValue(), TestConstants.TEST_USER_NAME, "Correct subject is" +
                " not set to assertion");
        assertEquals(assertion.getAttributeStatements().size(), 1, "Expected to have one attribute statement");
        assertEquals(assertion.getAttributeStatements().get(0).getAttributes().size(), 2, "Expected to have two " +
                "attributes");

        Map map = new HashMap();
        map.put(assertion.getAttributeStatements().get(0).getAttributes().get(0).getName(), assertion
                .getAttributeStatements().get(0).getAttributes().get(0).getName());
        map.put(assertion.getAttributeStatements().get(0).getAttributes().get(1).getName(), assertion
                .getAttributeStatements().get(0).getAttributes().get(1).getName());

        assertTrue(map.containsKey(TestConstants.CLAIM_URI1));
        assertTrue(map.containsKey(TestConstants.CLAIM_URI2));
    }

    @Test
    public void testSetSignature() throws Exception {

        TestUtils.prepareCredentials(x509Credential);
        Assertion assertion = buildAssertion();
        assertNull(assertion.getSignature(), "Initially a signature was present before signing");
        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(anyString())).thenReturn("org.wso2.carbon.identity.sso.saml.builders" +
                ".signature.DefaultSSOSigner");
        Assertion resultAssertion = SAMLSSOUtil.setSignature(assertion, TestConstants.RSA_SHA1_SIG_ALGO,
                TestConstants.SHA1_DIGEST_ALGO, x509Credential);
        assertNotNull(resultAssertion.getSignature(), "Signature not present in assertion");
        assertTrue(TestConstants.RSA_SHA1_SIG_ALGO.equalsIgnoreCase(resultAssertion.getSignature()
                .getSignatureAlgorithm()), "Signature algorithm is not the one which was set");
    }

    @Test
    public void testGetAttributes() throws Exception {

        prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.LOACALHOST_DOMAIN,
                TestConstants.LOACALHOST_DOMAIN);
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

    @Test
    public void validateACS() throws Exception {

        prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER,
                TestConstants.TRAVELOCITY_ISSUER);
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
        assertTrue(isACSValied, "Expected to ACS to be validated. But failed");
    }

    @Test
    public void validateACSWithoutIssuer() throws Exception {

        prepareIdentityPersistentManager(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER,
                Collections.emptyList());
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
        assertFalse(isACSValied, "Expected to ACS to be validated. But failed");
    }

    @Test
    public void validateACSWithACSInSP() throws Exception {

        List<String> acs = new ArrayList();
        acs.add(TestConstants.ACS_URL);
        prepareIdentityPersistentManager(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.TRAVELOCITY_ISSUER, acs);
        TestUtils.startTenantFlow(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        boolean isACSValied = SAMLSSOUtil.validateACS(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, TestConstants
                .TRAVELOCITY_ISSUER, TestConstants.ACS_URL);
        assertTrue(isACSValied, "No ACS configured in SAML SP. Hence expecting false");
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
        DefaultBootstrap.bootstrap();
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
        DefaultBootstrap.bootstrap();
        AuthnRequest authnRequest = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                HTTPConstants.HTTP_METHOD_GET, TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        SSOAuthnRequestValidator spInitSSOAuthnRequestValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator
                (authnRequest);
        assertNull(spInitSSOAuthnRequestValidator, "Expected SP init SSO Authn Request validator to be null");
    }

    @Test
    public void getSPInitValidatorWithNonExistingClass() throws Exception {

        SAMLSSOUtil.setSPInitSSOAuthnRequestValidator("org.wso2.carbon.identity.sso.saml.validators.NonExistingClass");
        DefaultBootstrap.bootstrap();
        AuthnRequest authnRequest = SAMLTestRequestBuilder.buildAuthnRequest(TestConstants.TRAVELOCITY_ISSUER, false, false,
                "GET", TestConstants.TRAVELOCITY_ISSUER, TestConstants.IDP_URL);
        SSOAuthnRequestValidator spInitSSOAuthnRequestValidator = SAMLSSOUtil.getSPInitSSOAuthnRequestValidator
                (authnRequest);
        assertNull(spInitSSOAuthnRequestValidator, "Expected SP init SSO Authn Request validator to be null");
    }

    private void prepareForGetIssuer() throws Exception {

        when(tenantManager.getTenantId(anyString())).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
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

    private void prepareForUserAttributes(String attrConsumerIndex, String issuer, String spName) {

        mockStatic(SSOServiceProviderConfigManager.class);
        when(SSOServiceProviderConfigManager.getInstance()).thenReturn(ssoServiceProviderConfigManager);
        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setAttributeConsumingServiceIndex(attrConsumerIndex);
        samlssoServiceProviderDO.setEnableAttributesByDefault(true);
        samlssoServiceProviderDO.setIssuer(issuer);
        ssoServiceProviderConfigManager.addServiceProvider(issuer, samlssoServiceProviderDO);
        when(ssoServiceProviderConfigManager.getServiceProvider(spName)).thenReturn(samlssoServiceProviderDO);
    }


    private Assertion buildAssertion() throws Exception {

        prepareForGetIssuer();
        mockStatic(IdentityUtil.class);
        mockStatic(IdentityTenantUtil.class);
        when(IdentityUtil.getServerURL(anyString(), anyBoolean(), anyBoolean()))
                .thenReturn(TestConstants.SAMPLE_SERVER_URL);
        prepareForUserAttributes(TestConstants.ATTRIBUTE_CONSUMER_INDEX, TestConstants.LOACALHOST_DOMAIN,
                TestConstants.LOACALHOST_DOMAIN);
        Map<String, String> inputAttributes = new HashMap<>();
        inputAttributes.put(TestConstants.CLAIM_URI1, TestConstants.CLAIM_VALUE1);
        inputAttributes.put(TestConstants.CLAIM_URI2, TestConstants.CLAIM_VALUE2);
        SAMLSSOAuthnReqDTO authnReqDTO = TestUtils.buildAuthnReqDTO(inputAttributes, TestConstants.SAMPLE_NAME_ID_FORMAT,
                TestConstants.LOACALHOST_DOMAIN, TestConstants.TEST_USER_NAME);

        authnReqDTO.setNameIDFormat(TestConstants.SAMPLE_NAME_ID_FORMAT);
        authnReqDTO.setIssuer(TestConstants.LOACALHOST_DOMAIN);
        Assertion assertion = SAMLSSOUtil.buildSAMLAssertion(authnReqDTO, new DateTime(00000000L), TestConstants
                .SESSION_ID);
        return assertion;
    }

    private void prepareIdentityPersistentManager(String attrConsumerIndex, String issuer, List acsList) throws
            IdentityException {

        SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
        samlssoServiceProviderDO.setAttributeConsumingServiceIndex(attrConsumerIndex);
        samlssoServiceProviderDO.setEnableAttributesByDefault(true);
        samlssoServiceProviderDO.setIssuer(issuer);
        samlssoServiceProviderDO.setAssertionConsumerUrls(acsList);
        when(identityPersistenceManager.getServiceProvider(any(Registry.class), anyString()))
                .thenReturn(samlssoServiceProviderDO);
        mockStatic(IdentityPersistenceManager.class);
        when(IdentityPersistenceManager.getPersistanceManager()).thenReturn(identityPersistenceManager);
    }
}
