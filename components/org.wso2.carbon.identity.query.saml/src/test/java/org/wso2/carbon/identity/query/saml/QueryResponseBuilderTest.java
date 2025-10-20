/*
 *  Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 */

package org.wso2.carbon.identity.query.saml;

import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.impl.AssertionImpl;
import org.opensaml.saml.saml2.core.impl.IssuerImpl;
import org.opensaml.saml.saml2.core.impl.ResponseImpl;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.query.saml.dto.InvalidItemDTO;
import org.wso2.carbon.identity.query.saml.exception.IdentitySAML2QueryException;
import org.wso2.carbon.identity.query.saml.util.OpenSAML3Util;
import org.wso2.carbon.identity.query.saml.util.SAMLQueryRequestConstants;
import org.opensaml.security.x509.X509Credential;
import org.wso2.carbon.identity.sso.saml.util.SAMLSSOUtil;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import static org.mockito.Mockito.mock;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test Class for the QueryResponseBuilder.
 */
public class QueryResponseBuilderTest {

    @Test
    public void testBuildforSuccess() throws Exception {

        DummyAssertion dummyAssertion = new DummyAssertion();
        List<Assertion> assertions = new ArrayList<>();
        SAMLSSOServiceProviderDO ssoIdpConfigs = new SAMLSSOServiceProviderDO();
        Response response = new DummyResponse();
        assertions.add(dummyAssertion);
        DummyIssuer issuer = new DummyIssuer();

        try (MockedStatic<OpenSAML3Util> openSaml = Mockito.mockStatic(OpenSAML3Util.class);
             MockedStatic<SAMLSSOUtil> ssoUtil = Mockito.mockStatic(SAMLSSOUtil.class);
             MockedStatic<IdentityTenantUtil> idTenantUtil = Mockito.mockStatic(IdentityTenantUtil.class);
             MockedStatic<ServerConfiguration> serverConfigStatic = Mockito.mockStatic(ServerConfiguration.class);
             MockedStatic<KeyStoreManager> keyStoreManagerStatic = Mockito.mockStatic(KeyStoreManager.class);
             MockedConstruction<SignKeyDataHolder> ignored = Mockito.mockConstruction(SignKeyDataHolder.class)) {

            // Static mocks for OpenSAML3Util
            openSaml.when(() -> OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer);
            openSaml.when(() -> OpenSAML3Util.setSignature(any(Response.class), any(String.class), any(String.class), any(X509Credential.class)))
                    .thenReturn(response);

            // Mock RealmService and TenantManager for SAMLSSOUtil
            RealmService realmService = mock(RealmService.class);
            TenantManager tenantManager = mock(TenantManager.class);
            Mockito.when(realmService.getTenantManager()).thenReturn(tenantManager);
            Mockito.when(tenantManager.getTenantId("test")).thenReturn(MultitenantConstants.SUPER_TENANT_ID);
            ssoUtil.when(SAMLSSOUtil::getRealmService).thenReturn(realmService);

            // IdentityTenantUtil.initializeRegistry should be a no-op
            idTenantUtil.when(() -> IdentityTenantUtil.initializeRegistry(MultitenantConstants.SUPER_TENANT_ID, "test"))
                    .then(invocation -> null);

            // Mock ServerConfiguration to provide key alias and avoid sign keystore path
            ServerConfiguration serverConfiguration = mock(ServerConfiguration.class);
            serverConfigStatic.when(ServerConfiguration::getInstance).thenReturn(serverConfiguration);
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_KEY_STORE_KEY_ALIAS))
                    .thenReturn("wso2carbon");
            // Keep SAML sign keystore related properties blank so isSignKeyStoreConfigured() returns false.
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_SAML_SIGN_KEY_STORE_LOCATION))
                    .thenReturn(null);
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_SAML_SIGN_KEY_STORE_TYPE))
                    .thenReturn(null);
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_SAML_SIGN_KEY_STORE_PASSWORD))
                    .thenReturn(null);
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_SAML_SIGN_KEY_STORE_KEY_ALIAS))
                    .thenReturn(null);
            Mockito.when(serverConfiguration.getFirstProperty(SignKeyDataHolder.SECURITY_SAML_SIGN_KEY_STORE_KEY_PASSWORD))
                    .thenReturn(null);

            // Mock KeyStoreManager and keystore/certs
            KeyStoreManager keyStoreManager = mock(KeyStoreManager.class);
            keyStoreManagerStatic.when(() -> KeyStoreManager.getInstance(MultitenantConstants.SUPER_TENANT_ID))
                    .thenReturn(keyStoreManager);
            PrivateKey privateKey = mock(PrivateKey.class);
            Mockito.when(keyStoreManager.getDefaultPrivateKey()).thenReturn(privateKey);

            KeyStore primaryKeyStore = mock(KeyStore.class);
            Mockito.when(keyStoreManager.getPrimaryKeyStore()).thenReturn(primaryKeyStore);

            X509Certificate cert = mock(X509Certificate.class);
            PublicKey publicKey = mock(PublicKey.class);
            Mockito.when(publicKey.getAlgorithm()).thenReturn("RSA");
            Mockito.when(cert.getPublicKey()).thenReturn(publicKey);
            Mockito.when(primaryKeyStore.getCertificateChain("wso2carbon")).thenReturn(new Certificate[]{cert});
            assertTrue(QueryResponseBuilder.build(assertions, ssoIdpConfigs, "test").getAssertions() != null);
        }
    }

    @Test
    public void testBuildforError() throws IdentitySAML2QueryException {

        DummyIssuer issuer = new DummyIssuer();
        DummyIssuer issuer2 = new DummyIssuer();
        List<InvalidItemDTO> invalidItems = new ArrayList<>();
        try (MockedStatic<OpenSAML3Util> openSaml = Mockito.mockStatic(OpenSAML3Util.class)) {
            openSaml.when(() -> OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer);
            Response testresponse1 = QueryResponseBuilder.build(invalidItems);
            openSaml.when(() -> OpenSAML3Util.getIssuer(anyString())).thenReturn(issuer2);
            invalidItems.add(new InvalidItemDTO(SAMLQueryRequestConstants.ValidationType.VAL_SUBJECT,
                    SAMLQueryRequestConstants.ValidationMessage.VAL_SUBJECT_ERROR));
            Response testresponse2 = QueryResponseBuilder.build(invalidItems);

            assertEquals(testresponse1.getStatus().getStatusCode().getValue(), null);
            assertEquals(testresponse1.getStatus().getStatusMessage().getMessage(), null);
            assertEquals(testresponse2.getStatus().getStatusMessage().getMessage(), "Request subject is invalid");
            assertEquals(testresponse2.getStatus().getStatusCode().getValue(), "urn:oasis:names:tc:SAML:2.0:status:Requester");
        }
    }

    @Test
    public void testBuildStatus() {

        Status dummyStatus1 = QueryResponseBuilder.buildStatus("teststatus1", "testmsg");
        Status dummyStatus2 = QueryResponseBuilder.buildStatus("teststatus2", null);
        assertEquals(dummyStatus1.getStatusMessage().getMessage(), "testmsg");
        assertEquals(dummyStatus2.getStatusMessage(), null);
        assertEquals(dummyStatus1.getStatusCode().getValue(), "teststatus1");
        assertEquals(dummyStatus2.getStatusCode().getValue(), "teststatus2");
    }

    @DataProvider(name = "provideValidationType")
    public Object[][] createValidationType() {

        String VAL_MESSAGE_BODY = "Validation Message Body";
        String INTERNAL_SERVER_ERROR = "Internal Server Error";
        String VAL_MESSAGE_TYPE = "Validation Message Type";
        String VAL_VERSION = "Validating the Version";
        String VAL_ISSUER = "Checking for Issuer";
        String VAL_SIGNATURE = "Validating Signature";
        String NO_ASSERTIONS = "No Assertions Matched";
        String VAL_ASSERTION_ID = "Invalid Assertion ID";
        String VAL_SUBJECT = "Invalid Subject";
        String VAL_ACTIONS = "No Actions";
        String VAL_RESOURCE = "No Resource";
        String VAL_AUTHN_QUERY = "No sessionIndex or AuthnContextClassRefs";
        String STRING_TO_OMELEMENT = "String convert to OMElement";
        String NULL_OMELEMENT = "OMElement is null";
        String VAL_VALIDATION_ERROR = "Validation error";
        String VAL_PROFILE_ENABLED = "Checking Assertion Query/Request profile enabled";

        String SUCCESS_CODE = "urn:oasis:names:tc:SAML:2.0:status:Success";
        String REQUESTOR_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        String IDENTITY_PROVIDER_ERROR = "urn:oasis:names:tc:SAML:2.0:status:Responder";
        String VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
        String AUTHN_FAILURE = "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed";
        String NO_PASSIVE = "urn:oasis:names:tc:SAML:2.0:status:NoPassive";
        String UNKNOWN_PRINCIPAL = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal";
        String NO_AUTHN_CONTEXT = "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext";
        return new Object[][]{
                {VAL_VERSION, VERSION_MISMATCH},
                {VAL_ISSUER, UNKNOWN_PRINCIPAL},
                {VAL_SIGNATURE, REQUESTOR_ERROR},
                {VAL_MESSAGE_TYPE, REQUESTOR_ERROR},
                {VAL_MESSAGE_BODY, REQUESTOR_ERROR},
                {NO_ASSERTIONS, NO_AUTHN_CONTEXT},
                {VAL_ASSERTION_ID, REQUESTOR_ERROR},
                {VAL_SUBJECT, REQUESTOR_ERROR},
                {VAL_ACTIONS, REQUESTOR_ERROR},
                {VAL_RESOURCE, REQUESTOR_ERROR},
                {VAL_AUTHN_QUERY, REQUESTOR_ERROR},
                {STRING_TO_OMELEMENT, IDENTITY_PROVIDER_ERROR},
                {NULL_OMELEMENT, IDENTITY_PROVIDER_ERROR},
                {VAL_VALIDATION_ERROR, REQUESTOR_ERROR},
                {INTERNAL_SERVER_ERROR, IDENTITY_PROVIDER_ERROR},
                {VAL_PROFILE_ENABLED, IDENTITY_PROVIDER_ERROR},
        };
    }

    @Test(dataProvider = "provideValidationType")
    public void testFilterStatusCode(String status, String response)  {

        assertEquals(QueryResponseBuilder.filterStatusCode(status), response);
    }

    class DummyIssuer extends IssuerImpl {

        protected DummyIssuer() {
            super("testNSU", "testELN", "testNSP");
        }

    }

    class DummyAssertion extends AssertionImpl {

        protected DummyAssertion() {
            super("testNSU", "testELN", "testNSP");
        }
    }

    class DummyResponse extends ResponseImpl {

        protected DummyResponse() {
            super("testNSU", "testELN", "testNSP");
        }
    }

}
