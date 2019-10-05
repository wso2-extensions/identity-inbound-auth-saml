/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
package org.wso2.carbon.identity.sso.saml.ui;

import org.apache.axiom.util.UIDGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.StatusMessage;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.StatusMessageBuilder;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import net.shibboleth.utilities.java.support.codec.Base64Support;
import org.w3c.dom.Element;
import org.w3c.dom.bootstrap.DOMImplementationRegistry;
import org.w3c.dom.ls.DOMImplementationLS;
import org.w3c.dom.ls.LSOutput;
import org.w3c.dom.ls.LSSerializer;
import org.wso2.carbon.identity.base.IdentityException;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

public class ErrorResponseBuilder {

    private static final Log log = LogFactory.getLog(ErrorResponseBuilder.class);

    //Do the bootstrap first
    static {
        Thread thread = Thread.currentThread();
        ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());

        try {
            InitializationService.initialize();

            org.opensaml.saml.config.SAMLConfigurationInitializer initializer_1 = new org.opensaml.saml.config.SAMLConfigurationInitializer();
            initializer_1.init();

            org.opensaml.saml.config.XMLObjectProviderInitializer initializer_2 = new org.opensaml.saml.config.XMLObjectProviderInitializer();
            initializer_2.init();

            org.opensaml.core.xml.config.XMLObjectProviderInitializer initializer_3 = new org.opensaml.core.xml.config.XMLObjectProviderInitializer();
            initializer_3.init();

            org.opensaml.core.xml.config.GlobalParserPoolInitializer initializer_4 = new org.opensaml.core.xml.config.GlobalParserPoolInitializer();
            initializer_4.init();

            org.opensaml.xmlsec.config.JavaCryptoValidationInitializer initializer_5 = new org.opensaml.xmlsec.config.JavaCryptoValidationInitializer();
            initializer_5.init();

            org.opensaml.xmlsec.config.XMLObjectProviderInitializer initializer_6 = new org.opensaml.xmlsec.config.XMLObjectProviderInitializer();
            initializer_6.init();

            org.opensaml.xmlsec.config.ApacheXMLSecurityInitializer initializer_7 = new org.opensaml.xmlsec.config.ApacheXMLSecurityInitializer();
            initializer_7.init();

            org.opensaml.xmlsec.config.GlobalSecurityConfigurationInitializer initializer_8 = new org.opensaml.xmlsec.config.GlobalSecurityConfigurationInitializer();
            initializer_8.init();

            org.opensaml.xmlsec.config.GlobalAlgorithmRegistryInitializer initializer_9 = new org.opensaml.xmlsec.config.GlobalAlgorithmRegistryInitializer();
            initializer_9.init();

        } catch (InitializationException e) {
            log.error("Error in bootstrapping the OpenSAML3 library", e);
        } finally {
            thread.setContextClassLoader(loader);
        }
    }

    private ErrorResponseBuilder() {
    }

    public static String generateErrorneousResponse() {
        Response response = new ResponseBuilder().buildObject();
        response.setIssuer(getIssuer());
        response.setStatus(buildStatus());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setID(UIDGenerator.generateUID());

        try {
            return encode(marshall(response));
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while encoding.", e);
            }
            return null;
        }
    }


    private static Status buildStatus() {

        Status stat = new StatusBuilder().buildObject();

        //Set the status code
        StatusCode statCode = new StatusCodeBuilder().buildObject();
        statCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Responder");
        stat.setStatusCode(statCode);
        StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
        statMesssage.setMessage("Error when processing the Authentication Request");
        stat.setStatusMessage(statMesssage);

        return stat;
    }

    private static String marshall(XMLObject xmlObject) throws org.wso2.carbon.identity.base.IdentityException {
        try {
            System.setProperty("javax.xml.parsers.DocumentBuilderFactory",
                    "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl");

            MarshallerFactory marshallerFactory = XMLObjectProviderRegistrySupport.getMarshallerFactory();
            Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);
            Element element = marshaller.marshall(xmlObject);

            ByteArrayOutputStream byteArrayOutputStrm = new ByteArrayOutputStream();
            DOMImplementationRegistry registry = DOMImplementationRegistry.newInstance();
            DOMImplementationLS impl =
                    (DOMImplementationLS) registry.getDOMImplementation("LS");
            LSSerializer writer = impl.createLSSerializer();
            LSOutput output = impl.createLSOutput();
            output.setByteStream(byteArrayOutputStrm);
            writer.write(element, output);
            return byteArrayOutputStrm.toString("UTF-8");
        } catch (Exception e) {
            log.error("Error Serializing the SAML Response");
            throw IdentityException.error("Error Serializing the SAML Response", e);
        }
    }

    private static Issuer getIssuer() {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setValue("WSO2 Identity Server");
        issuer.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        return issuer;
    }

    public static String encode(String authReq) {
        return Base64Support.encode(authReq.getBytes(StandardCharsets.UTF_8),
                        Base64Support.UNCHUNKED);
    }
}
