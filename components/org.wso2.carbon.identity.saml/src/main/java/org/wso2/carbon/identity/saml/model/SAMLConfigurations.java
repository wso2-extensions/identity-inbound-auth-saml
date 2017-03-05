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
package org.wso2.carbon.identity.saml.model;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SAMLConfigurations {

    private static SAMLConfigurations instance = new SAMLConfigurations();
    ;
    private String keyStoreLocation = System.getProperty("carbon.home") + File.separator + "resources" + File.separator
                                      +
                                      "security" + File
                                              .separator + "wso2carbon.jks";
    private String keyStoreType = "JKS";
    private String keyStorePassword = "wso2carbon";
    private String keyStoreAlias = "wso2carbon";
    private long samlResponseValidityPeriod = 5;
    private String ssoResponseHtml = "<html>\n" +
                                     "\t<body>\n" +
                                     "        \t<p>You are now redirected back to $acUrl \n" +
                                     "        \tIf the redirection fails, please click the post button.</p>\n" +
                                     "\n" +
                                     "        \t<form method='post' action='$acUrl'>\n" +
                                     "       \t\t\t<p>\n" +
                                     "\t\t\t\t\t<!--$params-->\n" +
                                     "                    <!--$additionalParams-->\n" +
                                     "        \t\t\t<button type='submit'>POST</button>\n" +
                                     "       \t\t\t</p>\n" +
                                     "       \t\t</form>\n" +
                                     "       \t\t<script type='text/javascript'>\n" +
                                     "        \t\tdocument.forms[0].submit();\n" +
                                     "        \t</script>\n" +
                                     "        </body>\n" +
                                     "</html>";
    private String idpEntityId = "localhost";
    private List<String> destinationUrls = new ArrayList<>();


    private SAMLConfigurations() {
        this.destinationUrls.add("https://localhost:9292/gateway");
    }

    public static SAMLConfigurations getInstance() {
        return instance;
    }

    public List<String> getDestinationUrls() {
        return destinationUrls;
    }

    public void setDestinationUrls(List<String> destinationUrls) {
        this.destinationUrls = destinationUrls;
    }

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
    }

    public String getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(String keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public long getSamlResponseValidityPeriod() {
        return samlResponseValidityPeriod;
    }

    public void setSamlResponseValidityPeriod(long samlResponseValidityPeriod) {
        this.samlResponseValidityPeriod = samlResponseValidityPeriod;
    }

    public String getSsoResponseHtml() {
        return ssoResponseHtml;
    }

    public void setSsoResponseHtml(String ssoResponseHtml) {
        this.ssoResponseHtml = ssoResponseHtml;
    }
}
