package org.wso2.carbon.identity.sso.saml.model;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.util.HashMap;
import java.util.Map;

public class SamlSSORequestWrapper extends HttpServletRequestWrapper {

    private Map extraParameters;

    public SamlSSORequestWrapper(HttpServletRequest request) {
        super(request);
        extraParameters= new HashMap();

    }

    public String getParameter(String name){

        if (extraParameters.containsKey(name)) {
            return (String) extraParameters.get(name);
        } else {
            return super.getParameter(name);
        }
    }

    public void setParameter(String name, String value){
        extraParameters.put(name, value);

    }


}
