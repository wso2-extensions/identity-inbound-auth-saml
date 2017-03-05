package org.wso2.carbon.identity.saml.wrapper;

import org.wso2.carbon.identity.gateway.common.model.sp.ResponseBuilderConfig;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SAMLResponseHandlerConfig implements Serializable {
    private static final long serialVersionUID = 6508235825726363156L;
    private ResponseBuilderConfig responseBuilderConfigs ;

    public SAMLResponseHandlerConfig(ResponseBuilderConfig responseBuilderConfigs) {
        this.responseBuilderConfigs = responseBuilderConfigs;
    }

    public String getAttributeConsumingServiceIndex() {
        return (String) responseBuilderConfigs.getProperties().get("attributeConsumingServiceIndex");
    }

    public String getCertAlias() {
        return (String) responseBuilderConfigs.getProperties().get("certificateAlias");
    }

    public String getDefaultAssertionConsumerUrl() {
        return (String) responseBuilderConfigs.getProperties().get("defaultAssertionConsumerUrl");
    }

    public String getDigestAlgorithmUri() {
        return (String) responseBuilderConfigs.getProperties().get("digestAlgorithmUri");
    }

    public String getLoginPageURL() {
        return (String) responseBuilderConfigs.getProperties().get("loginPageURL");
    }

    public String getNameIdFormat() {
        return (String) responseBuilderConfigs.getProperties().get("nameIDFormat");
    }

    public String[] getRequestedAudiences() {
        List requestedAudiencesList = (List) responseBuilderConfigs.getProperties().get("requestedAudiences");
        List<String> requestedAudiencesStringList = new ArrayList<String>();
        requestedAudiencesList.stream().forEach(v -> requestedAudiencesStringList.add((String) v));
        return requestedAudiencesStringList.stream().toArray(size -> new String[size]);
    }

    public String[] getRequestedRecipients() {
        List requestedRecipientList = (List) responseBuilderConfigs.getProperties().get("requestedAudiences");
        List<String> requestedRecipientStringList = new ArrayList<String>();
        requestedRecipientList.stream().forEach(v -> requestedRecipientStringList.add((String) v));
        return requestedRecipientStringList.stream().toArray(size -> new String[size]);
    }

    public String getSigningAlgorithmUri() {
        return (String) responseBuilderConfigs.getProperties().get("signingAlgorithmUri");
    }

    public boolean isDoEnableEncryptedAssertion() {
        return Boolean.parseBoolean((String) responseBuilderConfigs.getProperties().get("doEnableEncryptedAssertion"));
    }

    public boolean isDoSignAssertions() {
        return Boolean.valueOf((String) responseBuilderConfigs.getProperties().get("doSignAssertions"));
    }

    public boolean isDoSignResponse() {
        return Boolean.valueOf((String) responseBuilderConfigs.getProperties().get("doSignResponse"));
    }

    public boolean isDoSingleLogout() {
        return Boolean.valueOf((String) responseBuilderConfigs.getProperties().get("doSingleLogout"));
    }

    public boolean isEnableAttributesByDefault() {
        return Boolean.parseBoolean((String) responseBuilderConfigs.getProperties().get("enableAttributesByDefault"));
    }
}
