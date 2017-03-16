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

import java.util.ArrayList;
import java.util.List;

/**
 * Bean class that represents the SAML2 SSO Inbound Authenticator Configuration.
 * This class must read configuration from deployment.yaml.
 */
public class Config {

    private static Config instance = new Config();

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
    private String errorPageUrl = "https://localhost:2929/notifications";


    private Config() {
        this.destinationUrls.add("https://localhost:9292/gateway");
    }

    public static Config getInstance() {
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

    public String getSsoResponseHtml() {
        return ssoResponseHtml;
    }

    public void setSsoResponseHtml(String ssoResponseHtml) {
        this.ssoResponseHtml = ssoResponseHtml;
    }

    public String getErrorPageUrl() {
        return this.errorPageUrl;
    }

    public void setErrorPageUrl(String errorPageUrl) {
        this.errorPageUrl = errorPageUrl;
    }
}
