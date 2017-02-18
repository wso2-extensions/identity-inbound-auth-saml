package org.wso2.carbon.identity.saml.bean;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class SAMLConfigurations {

    private String keyStoreLocation = System.getProperty("carbon.home") + File.separator + "security" + File
            .separator + "wso2carbon.jks";;
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
    private static SAMLConfigurations instance = new SAMLConfigurations();


    public static SAMLConfigurations getInstance() {
        return instance;
    }


    private SAMLConfigurations(){
        this.destinationUrls.add("https://localhost:9292/gateway");
    }

    public String getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(String keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyStoreAlias() {
        return keyStoreAlias;
    }

    public void setKeyStoreAlias(String keyStoreAlias) {
        this.keyStoreAlias = keyStoreAlias;
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

    public String getIdpEntityId() {
        return idpEntityId;
    }

    public void setIdpEntityId(String idpEntityId) {
        this.idpEntityId = idpEntityId;
    }

    public List<String> getDestinationUrls() {
        return destinationUrls;
    }

    public void setDestinationUrls(List<String> destinationUrls) {
        this.destinationUrls = destinationUrls;
    }
}
