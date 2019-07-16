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

import org.testng.annotations.Test;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * Test Class for the X509CredentialImpl.
 */
public class X509CredentialImplTest {
    String modulusString = "00d56047acf652298e3fcdbb8cecbc32214722aa1625f88480cf570cee373ada932b140c29b00dc" +
            "44f6e59e7018dddca66b2f1c645dacb9d4a45459cfa8f7e33df";
    String exponentString = "18bc01730656bde47476f7cfbd3d8f9e15ede9c389814672dc161e349b08627fc885fe9d2442ae92" +
            "f0214c7e97cf0b9a9fc876df4f53517ab63d710f997b2779";

    BigInteger modulus = new BigInteger(modulusString, 16);
    BigInteger exponent = new BigInteger(exponentString, 16);

    X509CredentialImpl testclass = new X509CredentialImpl(modulus, exponent);

    public X509CredentialImplTest() throws InvalidKeySpecException,
            NoSuchAlgorithmException, CertificateParsingException {
    }

    @Test
    public void testGetEntityId() {

        assertEquals(testclass.getEntityId(), null);
    }

    @Test
    public void testGetUsageType() {

        assertEquals(testclass.getUsageType(), null);
    }

    @Test
    public void testGetKeyNames() {

        assertEquals(testclass.getKeyNames(), null);
    }

    @Test
    public void testGetPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException {

        RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(spec);
        assertEquals(testclass.getPublicKey(), publicKey);
    }

    @Test
    public void testGetPrivateKey() {

        assertEquals(testclass.getPrivateKey(), null);
    }

    @Test
    public void testGetSecretKey() {

        assertEquals(testclass.getSecretKey(), null);
    }

    @Test
    public void testGetCredentialContextSet() {

        assertEquals(testclass.getCredentialContextSet(), null);
    }

    @Test
    public void testGetCredentialType() {

        assertEquals(testclass.getCredentialType(), null);
    }

    @Test
    public void testGetEntityCertificateChain() {

        assertTrue(testEqualArray((ArrayList) testclass.getEntityCertificateChain(), new ArrayList<X509Certificate>()));
    }

    @Test
    public void testGetCRLs() {
        assertEquals(testclass.getCRLs(), null);
    }

    private boolean testEqualArray(ArrayList actual, ArrayList expected) {

        return Arrays.deepEquals(actual.toArray(), expected.toArray());
    }

}
