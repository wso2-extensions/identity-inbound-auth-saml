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

package org.wso2.carbon.identity.saml.inbound.test.module;

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
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.common.util.Constants;
import org.wso2.carbon.identity.saml.exception.SAML2SSOServerException;
import org.wso2.carbon.kernel.utils.CarbonServerInfo;

import javax.inject.Inject;
import javax.ws.rs.HttpMethod;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.file.Paths;
import java.util.List;

/**
 * Tests for IDP initiated SAML.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class SAMLIDPInitiatedTests {

    private static final Logger log = LoggerFactory.getLogger(SAMLInboundSPInitTests.class);

    @Inject
    private BundleContext bundleContext;

    @Inject
    private CarbonServerInfo carbonServerInfo;


    @Configuration
    public Option[] createConfiguration() {

        List<Option> optionList = SAMLInboundOSGiTestUtils.getDefaultSecurityPAXOptions();

        optionList.add(CoreOptions.systemProperty("java.security.auth.login.config")
                .value(Paths.get(SAMLInboundOSGiTestUtils.getCarbonHome(), "conf", "security", "carbon-jaas.config")
                        .toString()));

        return optionList.toArray(new Option[optionList.size()]);
    }

    /**
     * Testing successful authentication using idp initiated sso
     */
//    @Test
    public void testSAMLInboundAuthenticationIDPinit() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SP_ENTITY_ID + "=" + SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME, HttpMethod.GET, false);

            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" + SAMLInboundTestConstants
                            .AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
            Assert.assertNotNull(cookie);
        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case");
        }
    }

    /**
     * Test the content of successful authentication of idp init sso
     */
//    @Test
    public void testSAMLResponse() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SP_ENTITY_ID + "=" + SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME, HttpMethod.GET, false);

            String locationHeader = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.RELAY_STATE));
            Assert.assertTrue(locationHeader.contains(SAMLInboundTestConstants.EXTERNAL_IDP));

            String relayState = locationHeader.split(SAMLInboundTestConstants.RELAY_STATE + "=")[1];
            relayState = relayState.split(SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR)[0];

            urlConnection = SAMLInboundTestUtils.request
                    (SAMLInboundTestConstants.GATEWAY_ENDPOINT + "?" + SAMLInboundTestConstants.RELAY_STATE + "=" +
                            relayState + "&" + SAMLInboundTestConstants.ASSERTION + "=" + SAMLInboundTestConstants
                            .AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String cookie = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.SET_COOKIE, urlConnection);
            if (cookie != null) {
                cookie = cookie.split(Constants.GATEWAY_COOKIE + "=")[1];
                Assert.assertNotNull(cookie);
                String response = SAMLInboundTestUtils.getContent(urlConnection);
                if (response != null) {
                    String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
                    try {
                        Response samlResponseObject = SAMLInboundTestUtils.getSAMLResponse(samlResponse);
                        Assert.assertEquals(SAMLInboundTestConstants.AUTHENTICATED_USER_NAME, samlResponseObject
                                .getAssertions().get(0).getSubject().getNameID().getValue());
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
//    @Test
    public void testInvalidIssuer() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SP_ENTITY_ID + "=" + SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME + "dummy", HttpMethod.GET, false);
            Assert.assertEquals(500, urlConnection.getResponseCode());

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding");
        }
    }

    /**
     * Try to access through idp init sso without enabling idp init sso.
     */
    @Test
    public void testIDPInitSSODisabled() {
        ServiceProviderConfig serviceProviderConfig = SAMLInboundTestUtils.getServiceProviderConfigs
                (SAMLInboundTestConstants.SAMPLE_ISSUER_NAME, bundleContext);
        serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                .setProperty("idPInitSSOEnabled", "false");
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SP_ENTITY_ID + "=" + SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME, HttpMethod.GET, false);

            Assert.assertEquals(302, urlConnection.getResponseCode());
            String location = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(location.contains("STATUS"));

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding");
        } finally {
            serviceProviderConfig.getRequestValidationConfig().getRequestValidatorConfigs().get(0).getProperties()
                    .setProperty("idPInitSSOEnabled", "true");
        }
    }

    /**
     * Send a wrong ACS with IDP init request.
     */
//    @Test
    public void testIDPInitSSOWrongACS() {
        try {
            HttpURLConnection urlConnection = SAMLInboundTestUtils.request(SAMLInboundTestConstants.GATEWAY_ENDPOINT
                    + "?" + SAMLInboundTestConstants.SP_ENTITY_ID + "=" + SAMLInboundTestConstants
                    .SAMPLE_ISSUER_NAME + SAMLInboundTestConstants.QUERY_PARAM_SEPARATOR +
                    "acs=http://localhost:9092/invalidACS", HttpMethod.GET, false);
            Assert.assertEquals(302, urlConnection.getResponseCode());
            String location = SAMLInboundTestUtils.getResponseHeader(HttpHeaders.LOCATION, urlConnection);
            Assert.assertTrue(location.contains("notification"));

        } catch (IOException e) {
            Assert.fail("Error while running federated authentication test case with response decoding");
        }
    }


}
