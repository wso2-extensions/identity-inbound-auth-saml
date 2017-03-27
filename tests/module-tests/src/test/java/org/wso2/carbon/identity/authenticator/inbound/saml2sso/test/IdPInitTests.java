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
import org.wso2.carbon.identity.authenticator.inbound.saml2sso.exception.SAML2SSOServerException;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.common.util.Constants;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.file.Paths;
import java.util.List;
import java.util.Properties;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

/**
 * Tests for IDP initiated SAML.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class IdPInitTests {

    private static final Logger log = LoggerFactory.getLogger(SPInitTests.class);

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
    public void testSAMLInboundAuthenticationIDPinit() {
        try {
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

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        }
    }


    /**
     * Testing successful authentication using idp initiated sso
     */
    @Test
    public void testSAMLInboundAuthenticationIDPInitWithMinimumConfigs() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        Properties originalReqValidatorConfigs = serviceProviderConfig.getRequestValidationConfig()
                .getRequestValidatorConfigs().get(0).getProperties();

        try {
            Properties newReqValidatorConfigs = new Properties();
            newReqValidatorConfigs.put(SAML2AuthConstants.Config.Name.SP_ENTITY_ID, originalReqValidatorConfigs
                    .get(SAML2AuthConstants.Config.Name.SP_ENTITY_ID));
            newReqValidatorConfigs.put(SAML2AuthConstants.Config.Name.DEFAULT_ASSERTION_CONSUMER_URL,
                    originalReqValidatorConfigs
                            .get(SAML2AuthConstants.Config.Name.DEFAULT_ASSERTION_CONSUMER_URL));

            newReqValidatorConfigs.put(SAML2AuthConstants.Config.Name.ASSERTION_CONSUMER_URLS,
                    originalReqValidatorConfigs.get(SAML2AuthConstants.Config.Name.ASSERTION_CONSUMER_URLS));
            newReqValidatorConfigs.put(SAML2AuthConstants.Config.Name.IDP_INIT_SSO_ENABLED, "true");
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).setProperties
                    (newReqValidatorConfigs);

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

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).setProperties(originalReqValidatorConfigs);
        }
    }
    /**
     * Test the content of successful authentication of idp init sso
     */
    @Test
    public void testSAMLResponse() {
        try {
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

            String cookie = TestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = TestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(samlResponseObject.getAssertions().get(0)
                                                    .getSubject().getNameID().getValue(),
                                            TestConstants.AUTHENTICATED_USER_NAME);
                    } catch (SAML2SSOServerException e) {
                        Assert.fail("Error while building SAML response from the response");
                    }
                }
            }
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding");
        }
    }

    /**
     * Send a request with an invalid issuer and assert on response.
     */
    @Test
    public void testInvalidIssuer() {

        try {
            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                                                                + "?" + TestConstants.SP_ENTITY_ID + "=" + TestConstants
                    .SAMPLE_ISSUER_NAME + "dummy", HttpMethod.GET, false);
            Assert.assertEquals(urlConnection.getResponseCode(), 200);
            String response = TestUtils.getContent(urlConnection);
            Assert.assertNotNull(response);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
            Assert.assertEquals(samlResponseObject.getAssertions().size(), 0);
            String location = response.split("post' action='")[1].split("'>")[0];
            Assert.assertTrue(location.contains("notifications"));
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding");
        } catch (SAML2SSOServerException e) {
            Assert.fail("Error while building Response object from SAMLResponse message.");
        }
    }

    /**
     * Try to access through idp init sso without enabling idp init sso.
     */
    @Test
    public void testIDPInitSSODisabled() {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty(SAML2AuthConstants.Config.Name.IDP_INIT_SSO_ENABLED, "false");
        try {
            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                                                                + "?" + TestConstants.SP_ENTITY_ID + "=" + TestConstants
                    .SAMPLE_ISSUER_NAME, HttpMethod.GET, false);

            Assert.assertEquals(urlConnection.getResponseCode(), 200);
            String response = TestUtils.getContent(urlConnection);
            Assert.assertNotNull(response);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
            Assert.assertEquals(samlResponseObject.getAssertions().size(), 0);

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding.");
        } catch (SAML2SSOServerException e) {
            Assert.fail("Error while building Response object from SAMLResponse message.");
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty(SAML2AuthConstants.Config.Name.IDP_INIT_SSO_ENABLED, "true");
        }
    }

    /**
     * Send a wrong ACS with IDP init request.
     */
    @Test
    public void testIDPInitSSOWrongACS() {

        try {
            HttpURLConnection urlConnection = TestUtils.request(TestConstants.GATEWAY_ENDPOINT
                                                                + "?" + TestConstants.SP_ENTITY_ID + "=" + TestConstants
                    .SAMPLE_ISSUER_NAME + TestConstants.QUERY_PARAM_SEPARATOR +
                                                                "acs=http://localhost:9092/invalidACS", HttpMethod.GET, false);
            String response = TestUtils.getContent(urlConnection);
            Assert.assertEquals(urlConnection.getResponseCode(), 200);
            Assert.assertNotNull(response);
            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
            Assert.assertEquals(samlResponseObject.getAssertions().size(), 0);
            String location = response.split("post' action='")[1].split("'>")[0];
            Assert.assertTrue(location.contains("notifications"));
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding.");
        } catch (SAML2SSOServerException e) {
            Assert.fail("Error while building Response object from SAMLResponse message.");
        }
    }


}
