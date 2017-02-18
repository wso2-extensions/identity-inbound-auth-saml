package org.wso2.carbon.identity.saml.wrapper;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SAMLResponseHandlerConfig implements Serializable {
    private static final long serialVersionUID = 6508235825726363156L;
    private Properties properties;

    public SAMLResponseHandlerConfig(Properties properties) {
        this.properties = properties;
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) properties.get("defaultAssertionConsumerUrl");
    }

    public String getCertAlias() {
        return (String) properties.get("certificateAlias");
    }

    public boolean isDoSingleLogout() {
        return Boolean.valueOf((String) properties.get("doSingleLogout"));
    }

    public String getLoginPageURL() {
        return (String) properties.get("loginPageURL");
    }

    public boolean isDoSignResponse() {
        return Boolean.valueOf((String) properties.get("doSignResponse"));
    }

    public boolean isDoSignAssertions() {
        return Boolean.valueOf((String) properties.get("doSignAssertions"));
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) properties.get("attributeConsumingServiceIndex");
    }

    public String[] getRequestedAudiences() {
        List requestedAudiencesList = (List) properties.get("requestedAudiences");
        List<String> requestedAudiencesStringList = new ArrayList<String>();
        requestedAudiencesList.stream().forEach(v -> requestedAudiencesStringList.add((String) v));
        return requestedAudiencesStringList.stream().toArray(size -> new String[size]);
    }

    public String[] getRequestedRecipients() {
        List requestedRecipientList = (List) properties.get("requestedAudiences");
        List<String> requestedRecipientStringList = new ArrayList<String>();
        requestedRecipientList.stream().forEach(v -> requestedRecipientStringList.add((String) v));
        return requestedRecipientStringList.stream().toArray(size -> new String[size]);
    }

    public boolean isEnableAttributesByDefault() {
        return Boolean.parseBoolean((String) properties.get("enableAttributesByDefault"));
    }

    public String getNameIdFormat() {
        return (String) properties.get("nameIDFormat");
    }

    public boolean isDoEnableEncryptedAssertion() {
        return Boolean.parseBoolean((String) properties.get("doEnableEncryptedAssertion"));
    }

    public String getSigningAlgorithmUri() {
        return (String) properties.get("signingAlgorithmUri");
    }

    public String getDigestAlgorithmUri() {
        return (String) properties.get("digestAlgorithmUri");
    }

}
