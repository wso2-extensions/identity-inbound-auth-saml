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

package org.wso2.carbon.identity.sso.saml;

import org.apache.commons.lang.StringUtils;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOAuthnReqDTO;

import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.powermock.api.mockito.PowerMockito.when;

public class TestUtils {

    public static KeyStore loadKeyStoreFromFileSystem(String keyStorePath, String password, String type) {

        try (FileInputStream inputStream = new FileInputStream(keyStorePath)) {
            KeyStore keyStore = KeyStore.getInstance(type);
            keyStore.load(inputStream, password.toCharArray());
            return keyStore;
        } catch (Exception e) {
            String errorMsg = "Error loading the key store from the given location.";
            throw new SecurityException(errorMsg, e);
        }
    }

    public static String getFilePath(String fileName) {

        if (StringUtils.isNotBlank(fileName)) {
            return Paths.get(System.getProperty("user.dir"), "src", "test", "resources", "conf", fileName).toString();
        }
        return null;
    }

    public static void startTenantFlow(String tenantDomain) {

        String carbonHome = Paths.get(System.getProperty("user.dir"), "target").toString();
        System.setProperty("carbon.home", carbonHome);
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }

    public static void prepareCredentials(X509Credential x509Credential) throws KeyStoreException,
            UnrecoverableKeyException, NoSuchAlgorithmException {

        KeyStore keyStore = TestUtils.loadKeyStoreFromFileSystem(TestUtils
                .getFilePath(TestConstants.KEY_STORE_NAME), TestConstants.WSO2_CARBON, "JKS");
        X509Certificate[] issuerCerts = null;
        Certificate[] certificates;

        certificates = keyStore.getCertificateChain(TestConstants.WSO2_CARBON);
        issuerCerts = new X509Certificate[certificates.length];

        int i = 0;
        for (Certificate certificate : certificates) {
            issuerCerts[i++] = (X509Certificate) certificate;
        }
        when(x509Credential.getEntityCertificate()).thenReturn((X509Certificate) certificates[0]);
        when(x509Credential.getEntityCertificateChain()).thenReturn(Arrays.asList(issuerCerts));
        when(x509Credential.getPrivateKey()).thenReturn((PrivateKey) keyStore.getKey(TestConstants.WSO2_CARBON,
                TestConstants.WSO2_CARBON.toCharArray()));
        when(x509Credential.getPublicKey()).thenReturn(issuerCerts[0].getPublicKey());
    }

    public static ClaimMapping buildClaimMapping(String claimUri) {

        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        return claimMapping;
    }

    public static SAMLSSOAuthnReqDTO buildAuthnReqDTO(Map<String, String> attributes, String nameIDFormat, String issuer,
                                                String subjectName) {

        SAMLSSOAuthnReqDTO authnReqDTO = new SAMLSSOAuthnReqDTO();
        authnReqDTO.setUser(AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectName));
        authnReqDTO.setNameIDFormat(nameIDFormat);
        authnReqDTO.setIssuer(issuer);
        Map<ClaimMapping, String> userAttributes = new HashMap<>();

        for (Map.Entry<String, String> entry : attributes.entrySet()) {
            userAttributes.put(TestUtils.buildClaimMapping(entry.getKey()), entry.getValue());
        }
        authnReqDTO.getUser().setUserAttributes(userAttributes);
        return authnReqDTO;
    }
}
