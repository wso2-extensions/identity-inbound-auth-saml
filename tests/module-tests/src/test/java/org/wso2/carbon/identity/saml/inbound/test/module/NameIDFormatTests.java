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
import org.apache.commons.lang.StringUtils;
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

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.util.List;
import javax.inject.Inject;
import javax.ws.rs.HttpMethod;

/**
 * Tests for IDP initiated SAML.
 */
@Listeners(PaxExam.class)
@ExamReactorStrategy(PerSuite.class)
public class NameIDFormatTests {

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

    @Test
    public void testDefaultNameIDFormat() {
        testNameIdFormat(null);
    }

    @Test
    public void testCustomNameIDFormat() {
        testNameIdFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:userName");
    }
    /**
     * Test inbound authentication and successful statement on assertion without configuring nameIDformat.
     */
    private void testNameIdFormat(String inputNameId) {
        ServiceProviderConfig serviceProviderConfig = TestUtils.getServiceProviderConfigs
                (TestConstants.SAMPLE_ISSUER_NAME, bundleContext);

        String originalNameIDFormat = serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                .getProperty(SAML2AuthConstants.Config.Name.NAME_ID_FORMAT);
        serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                .remove(SAML2AuthConstants.Config.Name.NAME_ID_FORMAT);

        if (StringUtils.isNotEmpty(inputNameId)) {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .put(SAML2AuthConstants.Config.Name.NAME_ID_FORMAT, inputNameId);
        } else {
            inputNameId = originalNameIDFormat;
        }

        try {
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
                    (TestConstants.GATEWAY_ENDPOINT + "?" + TestConstants.RELAY_STATE + "=" + relayState +
                            "&" + TestConstants.ASSERTION + "=" +
                            TestConstants.AUTHENTICATED_USER_NAME, HttpMethod.GET, false);

            String response = TestUtils.getContent(urlConnection);

            String samlResponse = response.split("SAMLResponse' value='")[1].split("'>")[0];
            try {
                Response samlResponseObject = TestUtils.getSAMLResponse(samlResponse);
                Assert.assertEquals(inputNameId, samlResponseObject.getAssertions().get(0).getSubject().getNameID().getFormat());
            } catch (SAML2SSOServerException e) {
                Assert.fail("Error while asserting on encrypted assertions test case", e);
            }
        } catch (IOException e) {
            Assert.fail("Error while running testSAMLInboundAuthentication test case", e);
        } finally {
            serviceProviderConfig.getResponseBuildingConfig().getResponseBuilderConfigs().get(0).getProperties()
                    .put(SAML2AuthConstants.Config.Name.NAME_ID_FORMAT, originalNameIDFormat);


        }
    }
}
