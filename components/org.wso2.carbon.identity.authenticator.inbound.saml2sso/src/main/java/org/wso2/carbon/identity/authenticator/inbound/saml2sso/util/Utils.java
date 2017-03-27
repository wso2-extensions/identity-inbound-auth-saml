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

package org.wso2.carbon.identity.authenticator.inbound.saml2sso.util;

import org.apache.commons.lang.StringUtils;
import org.opensaml.xml.util.Base64;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Utilities needed for SAML2 SSO Inbound Authenticator.
 */
public class Utils {

    /**
     * TODO: ideally this method must be in identity.commons. However the one in identity.commons uses
     * TODO: java.util.Base64 which doesn't work here. Only the OpenSAML Base64 decoder works. Until then duplicating
     * TODO: this method.
     * Decode X509 certificate.
     *
     * @param encodedCert Base64 encoded certificate
     * @return Decoded <code>Certificate</code>
     * @throws java.security.cert.CertificateException Error when decoding certificate
     */
    public static Certificate decodeCertificate(String encodedCert) throws CertificateException {

        if (StringUtils.isNotBlank(encodedCert)) {
            byte[] bytes = Base64.decode(encodedCert);
            if (bytes == null || bytes.length == 0) {
                throw new CertificateException("Encoded certificate is invalid: " + encodedCert);
            }
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(bytes));
            return cert;
        } else {
            throw new CertificateException("Encoded certificate is empty: " + encodedCert);
        }
    }
}
