<%@page import="org.apache.axis2.context.ConfigurationContext" %>
<%@page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.idp.mgt.IdentityProviderManager" %>
<%@page import="org.wso2.carbon.identity.idp.metadata.saml2.builder.DefaultIDPMetadataBuilder"%>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="org.wso2.carbon.context.CarbonContext" %>
<%@ page import="org.wso2.carbon.identity.application.common.model.IdentityProvider" %>
<%@ page import="org.wso2.carbon.identity.idp.metadata.saml2.builder.IDPMetadataBuilder" %>
<%@ page import="org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig" %>
<%@ page import="org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants" %>
<%@ page trimDirectiveWhitespaces="true" %>
<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }//TODO remove
    String BUNDLE = "org.wso2.carbon.idp.mgt.ui.i18n.Resources";
    try {
        IdentityProviderManager idpManager = IdentityProviderManager.getInstance();
        String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        IdentityProvider residentIdentityProvider = idpManager.getResidentIdP(tenantDomain);
        IDPMetadataBuilder builder = new DefaultIDPMetadataBuilder();
        String wantAuthRequestSigned = request.getParameter("samlAuthRequestSigned");
        builder.setWantAuthRequestSigned(Boolean.parseBoolean(wantAuthRequestSigned));
        FederatedAuthenticatorConfig[] federatedAuthenticatorConfigs = residentIdentityProvider.
                getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig samlFederatedAuthenticatorConfig = null;
        for (int i = 0; i < federatedAuthenticatorConfigs.length; i++) {
            if (federatedAuthenticatorConfigs[i].getName().equals(IdentityApplicationConstants.Authenticator.SAML2SSO.
                    NAME)) {
                samlFederatedAuthenticatorConfig = federatedAuthenticatorConfigs[i];
                break;
            }
        }
        if (samlFederatedAuthenticatorConfig == null) {
            throw new Exception("SAML configuration could not be loaded.");
        }
        String metadata = builder.build(samlFederatedAuthenticatorConfig);

        out.clearBuffer();
        byte metaBytes[] = metadata.getBytes();
        response.setHeader("Content-Disposition", "attachment;filename=\"" + "metadata.xml" + "\"");
        response.setHeader("Content-Type", "application/samlmetadata+xml;");
        response.setHeader("Accept-Ranges", "bytes");
        response.setHeader("Content-Length", String.valueOf(metaBytes.length));

        for(int i = 0; i < metaBytes.length; i++){
            out.write(metaBytes[i]);
        }

    } catch (Exception e) {
        CarbonUIMessage.sendCarbonUIMessage("Error downloading metadata file", CarbonUIMessage.INFO, request);
    } finally {
    }
%>
<script type="text/javascript">
    location.href = "add_service_provider.jsp";
</script>
