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

import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.Base64;
import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.gateway.common.model.sp.ServiceProviderConfig;
import org.wso2.carbon.identity.gateway.store.ServiceProviderConfigStore;
import org.wso2.carbon.identity.saml.exception.SAMLServerException;
import org.wso2.carbon.identity.saml.util.SAMLSSOUtil;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Utilities for SAML inbound tests.
 */
public class SAMLInboundTestUtils {

    public static HttpURLConnection request(String path, String method, boolean keepAlive) throws IOException {

        URL url = new URL(path);

        HttpURLConnection httpURLConnection = null;

        httpURLConnection = (HttpURLConnection) url.openConnection();

        httpURLConnection.setRequestMethod(method);
        if (!keepAlive) {
            httpURLConnection.setRequestProperty("CONNECTION", "CLOSE");
        }
        return httpURLConnection;

    }

    public static String getContent(HttpURLConnection urlConn) throws IOException {
        return new String(IOUtils.toByteArray(urlConn.getInputStream()), Charsets.UTF_8);
    }

    public static String getResponseHeader(String headerName, HttpURLConnection urlConnection) {
        return ((HttpURLConnection) urlConnection).getHeaderField(headerName);
    }


    public static Response getSAMLResponse(String samlResponse) throws SAMLServerException {
        String decodedResponse = new String(Base64.decode(samlResponse));
        XMLObject xmlObject = SAMLSSOUtil.SAMLAssertion.unmarshall(decodedResponse);

        return (Response) xmlObject;
    }

    public static ServiceProviderConfig getServiceProviderConfigs(String uniqueId, BundleContext bundleContext) {
        ServiceProviderConfigStore serviceProviderConfigStore = bundleContext.getService(bundleContext
                .getServiceReference(ServiceProviderConfigStore.class));
        return serviceProviderConfigStore.getServiceProvider(uniqueId);
    }
}
