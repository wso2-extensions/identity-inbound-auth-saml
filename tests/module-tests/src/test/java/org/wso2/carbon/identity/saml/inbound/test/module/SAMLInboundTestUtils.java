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
