/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.authenticator.inbound.saml2sso.test;

import com.google.common.net.HttpHeaders;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.ops4j.pax.exam.Configuration;
import org.ops4j.pax.exam.CoreOptions;
import org.ops4j.pax.exam.Option;
import org.ops4j.pax.exam.spi.reactors.ExamReactorStrategy;
import org.ops4j.pax.exam.spi.reactors.PerSuite;
import org.ops4j.pax.exam.testng.listener.PaxExam;
import org.osgi.framework.BundleContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;
import org.testng.annotations.Listeners;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthConstants;
import org.wso2.carbon.identity.auth.saml2.common.SAML2AuthUtils;
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/**
 * Tests for IDP initiated SAML.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class ClaimTests {

    private static final Logger log = LoggerFactory.getLogger(InitialTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = OSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(OSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    /**
     * Testing successful authentication using idp initiated sso
     */
    @Test
    public void testClaimsInEncryptedAssertionIDPInit() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        Properties originalResponseBuilderConfigs = (Properties) serviceProviderConfig.getResponseBuildingConfig()
                .getResponseBuilderConfigs().get(0).getProperties().clone();
        Properties originalRequestValidatorConfigs = (Properties) serviceProviderConfig.getRequestValidationConfig()
                .getRequestValidatorConfigs().get(0).getProperties().clone();

        try {
            serviceProviderConfig.getResponseBuildingConfig()
                    .getResponseBuilderConfigs().get(0).getProperties().put(SAML2AuthConstants.Config.Name
                    .AUTHN_RESPONSE_ENCRYPTED, "true");
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .put(SAML2AuthConstants.Config.Name.IDP_INIT_SSO_ENABLED, "true");
            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + TestConstants.SP_ENTITY_ID + "=" + TestConstants
                    .SAMPLE_ISSUER_NAME, HttpMethod.GET, false);

            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" + TestConstants
                            .AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assertion assertion = TestUtils.decryptAssertion(samlResponseObject);
                List<Attribute> attributes = assertion.getAttributeStatements().get(0).getAttributes();
                // Need to fix intermittent failure
//                Assert.assertTrue(attributes.size() == 3);

            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).setProperties
                    (originalResponseBuilderConfigs);
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).setProperties
                    (originalRequestValidatorConfigs);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testSAMLSPInitResponseClaimsWithoutASCIConfigured() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        Properties originalResponseBuilderConfigs = (Properties) serviceProviderConfig.getResponseBuildingConfig()
                .getResponseBuilderConfigs().get(0).getProperties().clone();
        Properties originalRequestValidatorConfigs = (Properties) serviceProviderConfig.getRequestValidationConfig()
                .getRequestValidatorConfigs().get(0).getProperties().clone();

        try {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .remove(SAML2AuthConstants.Config.Name.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .remove(SAML2AuthConstants.Config.Name.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
                Assert.assertTrue(attributes.size() == 0);
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }

        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).setProperties
                    (originalResponseBuilderConfigs);
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).setProperties
                    (originalRequestValidatorConfigs);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testClaimsWithoutProfile() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String originalProfile = serviceProviderConfig.getClaimConfig().getProfile();

        try {
            serviceProviderConfig.getClaimConfig().setProfile(null);
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
                Assert.assertTrue(attributes.size() == 3);
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }


        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getClaimConfig().setProfile(originalProfile);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testClaimsWithNonExistingProfile() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String originalProfile = serviceProviderConfig.getClaimConfig().getProfile();

        try {
            serviceProviderConfig.getClaimConfig().setProfile("NonExistingProfile");
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
                Assert.assertTrue(attributes.size() == 0);
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }


        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getClaimConfig().setProfile(originalProfile);
        }
    }


    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testClaimsWithDefaultProfile() {

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String originalProfile = serviceProviderConfig.getClaimConfig().getProfile();

        try {
            serviceProviderConfig.getClaimConfig().setProfile("default");
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }


        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getClaimConfig().setProfile(originalProfile);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testClaimsWithInheritedDialect() {

        String sp2GenderClaim = "http://sample.sp2.org/claims/gender";
        String sp2FullNameClaim = "http://sample.sp2.org/claims/fullname";
        String sp3EmailClaim = "http://sample.sp3.org/claims/email";

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String originalProfile = serviceProviderConfig.getClaimConfig().getProfile();
        String originalDialectUri = serviceProviderConfig.getClaimConfig().getDialectUri();

        try {
            serviceProviderConfig.getClaimConfig().setProfile("default");
            serviceProviderConfig.getClaimConfig().setDialectUri("http://sample.sp3.org/claims");
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
                Map<String, String> attributeMap = new HashMap<>();
                attributes.stream().forEach(attribute -> attributeMap.put(attribute.getName(), attribute.getName()));
                Assert.assertNotNull(attributeMap.get(sp2FullNameClaim));
                Assert.assertNotNull(attributeMap.get(sp2GenderClaim));
                Assert.assertNotNull(attributeMap.get(sp3EmailClaim));

            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getClaimConfig().setProfile(originalProfile);
            serviceProviderConfig.getClaimConfig().setDialectUri(originalDialectUri);
        }
    }

    /**
     * Testing the content of the SAML response.
     */
    @Test
    public void testClaimsWithInheritedDialectWithoutProfile() {

        String sp2GenderClaim = "http://sample.sp2.org/claims/gender";
        String sp2FullNameClaim = "http://sample.sp2.org/claims/fullname";
        String sp3EmailClaim = "http://sample.sp3.org/claims/email";

        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        String originalProfile = serviceProviderConfig.getClaimConfig().getProfile();
        String originalDialectUri = serviceProviderConfig.getClaimConfig().getDialectUri();

        try {
            serviceProviderConfig.getClaimConfig().setProfile(null);
            serviceProviderConfig.getClaimConfig().setDialectUri("http://sample.sp3.org/claims");
            AuthnRequest samlRequest = TestUtils.buildAuthnRequest("https://localhost:9292/gateway",
                    false, false, TestConstants.SAMPLE_ISSUER_NAME, TestConstants.ACS_URL);
            String samlRequestString = SAML2AuthUtils.encodeForRedirect(samlRequest);
            SAML2AuthUtils.encodeForPost(SAML2AuthUtils.marshall(samlRequest));

            StringBuilder httpQueryString = new StringBuilder(SAML2AuthConstants.SAML_REQUEST + "=" + samlRequestString);
            httpQueryString.append("&" + SAML2AuthConstants.RELAY_STATE + "=" + URLEncoder.encode("relayState",
                    StandardCharsets.UTF_8.name()).trim());
            SAML2AuthUtils.addSignatureToHTTPQueryString(httpQueryString, "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
                    SAML2AuthUtils.getServerCredentials());

            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                    + "?" + httpQueryString.toString(), HttpMethod.GET, false);
            String locationHeader = TestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(TestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(TestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(TestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(TestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = TestUtils.request
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" +
                            relayState + "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);

            cookie = cookie.split(org.wso2.carbon.identity.gateway.common.util.Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
            String response = TestUtils.getContent(urlConnection);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(samlResponseObject.getAssertions().get(0).getSubject().getNameID().getValue(),
                        TestConstants.AUTHENTICATED_USER_NAME);
                List<Attribute> attributes = samlResponseObject.getAssertions().get(0).getAttributeStatements().get(0)
                        .getAttributes();
                Map<String, String> attributeMap = new HashMap<>();
                attributes.stream().forEach(attribute -> attributeMap.put(attribute.getName(), attribute.getName()));
                Assert.assertNotNull(attributeMap.get(sp2FullNameClaim));
                Assert.assertNotNull(attributeMap.get(sp2GenderClaim));
                Assert.assertNotNull(attributeMap.get(sp3EmailClaim));

            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while building response object", e);
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLResponse test case", e);
        } finally {
            serviceProviderConfig.getClaimConfig().setProfile(originalProfile);
            serviceProviderConfig.getClaimConfig().setDialectUri(originalDialectUri);
        }
    }


}
