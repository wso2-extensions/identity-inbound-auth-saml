<!--
~ Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
~
~ WSO2 Inc. licenses this file to you under the Apache License,
~ Version 2.0 (the "License"); you may not use this file except
~ in compliance with the License.
~ You may obtain a copy of the License at
~
~ http://www.apache.org/licenses/LICENSE-2.0
~
~ Unless required by applicable law or agreed to in writing,
~ software distributed under the License is distributed on an
~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
~ KIND, either express or implied. See the License for the
~ specific language governing permissions and limitations
~ under the License.
-->
<%@page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOUIConstants" %>
<%@page import="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOUIUtil" %>
<%@page import="org.wso2.carbon.identity.sso.saml.ui.client.SAMLSSOConfigServiceClient" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIMessage" %>
<%@ page import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ResourceBundle" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.core.util.IdentityUtil" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.common.SAMLSSOProviderConstants" %>

<jsp:useBean id="samlSsoServuceProviderConfigBean"
             type="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOProviderConfigBean"
             class="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOProviderConfigBean"
             scope="session"/>
<jsp:setProperty name="samlSsoServuceProviderConfigBean" property="*"/>

<script type="text/javascript" src="global-params.js"></script>
<script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
<script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
<script type="text/javascript" src="../carbon/admin/js/main.js"></script>


<%
    String httpMethod = request.getMethod();
    if (!"post".equalsIgnoreCase(httpMethod)) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
    }

    String backendServerURL;
    ConfigurationContext configContext;
    String cookie;
    String user = null;
    SAMLSSOConfigServiceClient client;
    session.setAttribute(SAMLSSOUIConstants.CONFIG_CLIENT, null);
    String spName = (String) session.getAttribute("application-sp-name");
    session.removeAttribute("application-sp-name");
    boolean status = false;
    String attributeConsumingServiceIndex = null;

    backendServerURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
    configContext = (ConfigurationContext) config.getServletContext().getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
    cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);
    String BUNDLE = "org.wso2.carbon.identity.sso.saml.ui.i18n.Resources";
    ResourceBundle resourceBundle = ResourceBundle.getBundle(BUNDLE, request.getLocale());
    SAMLSSOServiceProviderDTO serviceProviderDTO = null;
    try {
        client = new SAMLSSOConfigServiceClient(cookie, backendServerURL, configContext);

        serviceProviderDTO = new SAMLSSOServiceProviderDTO();
        boolean isEditingSP = false;
        if ("editServiceProvider".equals(SAMLSSOUIUtil.getSafeInput(request, "SPAction"))) {
            isEditingSP = true;
            serviceProviderDTO.setIssuer(SAMLSSOUIUtil.getSafeInput(request, "hiddenIssuer"));
            serviceProviderDTO.setIssuerQualifier(SAMLSSOUIUtil.getSafeInput(request, "hiddenIssuerQualifier"));
        } else {
            serviceProviderDTO.setIssuer(SAMLSSOUIUtil.getSafeInput(request, "issuer"));
            serviceProviderDTO.setIssuerQualifier(SAMLSSOUIUtil.getSafeInput(request, "issuerQualifier"));
        }

        serviceProviderDTO.setAssertionConsumerUrls(SAMLSSOUIUtil.getSafeInput(request, "assertionConsumerURLs")
                .split(","));
        serviceProviderDTO.setDefaultAssertionConsumerUrl(SAMLSSOUIUtil.getSafeInput(request,
                "defaultAssertionConsumerURL"));
        serviceProviderDTO.setSigningAlgorithmURI(SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.
                SAML_SSO_SIGNING_ALGORITHM));
        serviceProviderDTO.setDigestAlgorithmURI(SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.
                SAML_SSO_DIGEST_ALGORITHM));
        serviceProviderDTO.setAssertionEncryptionAlgorithmURI(SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.
                SAML_SSO_ASSERTION_ENCRYPTION_ALGORITHM));
        serviceProviderDTO.setKeyEncryptionAlgorithmURI(SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.
                SAML_SSO_KEY_ENCRYPTION_ALGORITHM));

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_SINGLE_LOGOUT))) {
            serviceProviderDTO.setDoSingleLogout(true);
            if (StringUtils.isNotBlank(request.getParameter(SAMLSSOUIConstants.SLO_RESPONSE_URL))) {
                serviceProviderDTO.setSloResponseURL(request.getParameter(SAMLSSOUIConstants.SLO_RESPONSE_URL));
            }
            if (StringUtils.isNotBlank(request.getParameter(SAMLSSOUIConstants.SLO_REQUEST_URL))) {
                serviceProviderDTO.setSloRequestURL(request.getParameter(SAMLSSOUIConstants.SLO_REQUEST_URL));
            }
            if (SAMLSSOProviderConstants.HTTP_REDIRECT_BINDING.equals(request.getParameter
                    (SAMLSSOUIConstants.SLO_TYPE))) {
                serviceProviderDTO.setDoFrontChannelLogout(true);
                serviceProviderDTO.setFrontChannelLogoutBinding(SAMLSSOProviderConstants.HTTP_REDIRECT_BINDING);
            }
            if (SAMLSSOProviderConstants.HTTP_POST_BINDING.equals(request.getParameter(SAMLSSOUIConstants.SLO_TYPE))) {
                serviceProviderDTO.setDoFrontChannelLogout(true);
                serviceProviderDTO.setFrontChannelLogoutBinding(SAMLSSOProviderConstants.HTTP_POST_BINDING);
            }
        }
        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_RESPONSE_SIGNATURE))) {
            serviceProviderDTO.setDoSignResponse(true);
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_ASSERTION_QUERY_REQUEST_PROFILE))) {
            serviceProviderDTO.setAssertionQueryRequestProfileEnabled(true);
        }

        if (request.getParameter(SAMLSSOUIConstants.SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES) != null) {
            serviceProviderDTO.setSupportedAssertionQueryRequestTypes(request.getParameter(SAMLSSOUIConstants.SUPPORTED_ASSERTION_QUERY_REQUEST_TYPES));
        }

        if (request.getParameter(SAMLSSOUIConstants.ENABLE_SAML2_ARTIFACT_BINDING) != null) {

            serviceProviderDTO.setEnableSAML2ArtifactBinding(true);
        }


        if (request.getParameter(SAMLSSOUIConstants.ENABLE_SIGNATURE_VALIDATION_IN_ARTIFACT_RESOLVE) != null) {

            serviceProviderDTO.setDoValidateSignatureInArtifactResolve(true);
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_ASSERTION_SIGNATURE))) {
            serviceProviderDTO.setDoSignAssertions(true);
        }

        serviceProviderDTO.setNameIDFormat(request.getParameter(SAMLSSOUIConstants.NAME_ID_FORMAT));

        if (serviceProviderDTO.getNameIDFormat() != null) {
            serviceProviderDTO.setNameIDFormat(serviceProviderDTO.getNameIDFormat().replace(":", "/"));
        }

        if (request.getParameter(SAMLSSOUIConstants.ENABLE_ATTRIBUTE_PROFILE) != null) {
            serviceProviderDTO.setRequestedClaims(samlSsoServuceProviderConfigBean.getSelectedClaimsAttay());
            serviceProviderDTO.setEnableAttributeProfile(true);

            if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_DEFAULT_ATTRIBUTE_PROFILE_HIDDEN))) {
                serviceProviderDTO.setEnableAttributesByDefault(true);
            }
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_NAME_ID_CLAIM_URI_HIDDEN))) {
            serviceProviderDTO.setNameIdClaimUri(request.getParameter(SAMLSSOUIConstants.NAME_ID_CLAIM));
        }


        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_AUDIENCE_RESTRICTION))) {
            serviceProviderDTO.setRequestedAudiences(samlSsoServuceProviderConfigBean.getSelectedAudiencesArray());
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_RECIPIENTS))) {
            serviceProviderDTO.setRequestedRecipients(samlSsoServuceProviderConfigBean.getSelectedRecipientsArray());
        }

        if (request.getParameter(SAMLSSOUIConstants.LOGIN_PAGE_URL) != null && !"null".equals(request.getParameter(SAMLSSOUIConstants.LOGIN_PAGE_URL))) {
            serviceProviderDTO.setLoginPageURL(request.getParameter(SAMLSSOUIConstants.LOGIN_PAGE_URL));
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_ATTRIBUTE_PROFILE))) {
            String claimsCountParameter = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.CLAIM_PROPERTY_COUNTER);
            if (IdentityUtil.isNotBlank(claimsCountParameter)) {
                int claimsCount = Integer.parseInt(claimsCountParameter);
                for (int i = 0; i < claimsCount; i++) {
                    String claim = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.CLAIM_PROPERTY_NAME + i);
                    if (IdentityUtil.isNotBlank(claim)) {
                        String[] currentClaims = serviceProviderDTO.getRequestedClaims();
                        boolean isClaimAlreadyAdded = false;
                        for (String currentClaim : currentClaims) {
                            if (claim.equals(currentClaim)) {
                                isClaimAlreadyAdded = true;
                                break;
                            }
                        }
                        if (!isClaimAlreadyAdded) {
                            serviceProviderDTO.addRequestedClaims(claim);
                        }
                    }
                }
            }
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_AUDIENCE_RESTRICTION))) {
            String audiencesCountParameter = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.AUDIENCE_PROPERTY_COUNTER);
            if (IdentityUtil.isNotBlank(audiencesCountParameter)) {
                int audiencesCount = Integer.parseInt(audiencesCountParameter);
                for (int i = 0; i < audiencesCount; i++) {
                    String audience = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.AUDIENCE_PROPERTY_NAME + i);
                    if (IdentityUtil.isNotBlank(audience)) {
                        String[] currentAudiences = serviceProviderDTO.getRequestedAudiences();
                        boolean isAudienceAlreadyAdded = false;
                        for (String currentAudience : currentAudiences) {
                            if (audience.equals(currentAudience)) {
                                isAudienceAlreadyAdded = true;
                                break;
                            }
                        }
                        if (!isAudienceAlreadyAdded) {
                            serviceProviderDTO.addRequestedAudiences(audience);
                        }
                    }
                }
            }
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_RECIPIENTS))) {
            String recipientCountParameter = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.RECIPIENT_PROPERTY_COUNTER);
            if (IdentityUtil.isNotBlank(recipientCountParameter)) {
                int recipientCount = Integer.parseInt(recipientCountParameter);
                for (int i = 0; i < recipientCount; i++) {
                    String recipient = SAMLSSOUIUtil.getSafeInput(request, SAMLSSOUIConstants.RECIPIENT_PROPERTY_NAME + i);
                    if (IdentityUtil.isNotBlank(recipient)) {
                        String[] currentRecipients = serviceProviderDTO.getRequestedRecipients();
                        boolean isRecipientAlreadyAdded = false;
                        for (String currentRecipient : currentRecipients) {
                            if (recipient.equals(currentRecipient)) {
                                isRecipientAlreadyAdded = true;
                                break;
                            }
                        }
                        if (!isRecipientAlreadyAdded) {
                            serviceProviderDTO.addRequestedRecipients(recipient);
                        }
                    }
                }
            }
        }

        serviceProviderDTO.setAttributeConsumingServiceIndex(SAMLSSOUIUtil.getSafeInput(request, "attributeConsumingServiceIndex"));

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_IDP_INIT_SSO))) {
            serviceProviderDTO.setIdPInitSSOEnabled(true);
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_IDP_INIT_SLO))) {
            serviceProviderDTO.setIdPInitSLOEnabled(true);
            String returnToUrls = SAMLSSOUIUtil.getSafeInput(request, "idpInitSLOReturnToURLs");
            if (StringUtils.isNotBlank(returnToUrls)) {
                serviceProviderDTO.setIdpInitSLOReturnToURLs(returnToUrls.split(","));
            }
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_ENC_ASSERTION))) {
            serviceProviderDTO.setDoEnableEncryptedAssertion(true);
            serviceProviderDTO.setCertAlias(SAMLSSOUIUtil.getSafeInput(request, "alias"));
        }

        if (Boolean.parseBoolean(request.getParameter(SAMLSSOUIConstants.ENABLE_SIG_VALIDATION))) {
            serviceProviderDTO.setDoValidateSignatureInRequests(true);
            serviceProviderDTO.setCertAlias(SAMLSSOUIUtil.getSafeInput(request, "alias"));
        }
    
        if (StringUtils.isNotBlank(request.getParameter(SAMLSSOUIConstants.IDP_ENTITY_ID_ALIAS))) {
            serviceProviderDTO.setIdpEntityIDAlias(SAMLSSOUIUtil.getSafeInput(request,
                    SAMLSSOUIConstants.IDP_ENTITY_ID_ALIAS));
        }

        if (isEditingSP) {
            client.removeServiceProvier(serviceProviderDTO.getIssuer());
            if (StringUtils.isNotBlank(serviceProviderDTO.getIssuerQualifier())) {
                serviceProviderDTO.setIssuer(SAMLSSOUIUtil.getIssuerWithoutQualifier(serviceProviderDTO.getIssuer()));
            }
        }
        status = client.addServiceProvider(serviceProviderDTO);
        if (status) {
            String issuer = serviceProviderDTO.getIssuer();
            if (StringUtils.isNotBlank(serviceProviderDTO.getIssuerQualifier())) {
                issuer = SAMLSSOUIUtil.getIssuerWithQualifier(serviceProviderDTO.getIssuer(),
                        serviceProviderDTO.getIssuerQualifier());
            }
            attributeConsumingServiceIndex = client.getServiceProvider(issuer).getAttributeConsumingServiceIndex();
        }
        samlSsoServuceProviderConfigBean.clearBean();
        
        String message;
        if (status) {
            if (isEditingSP) {
                message = resourceBundle.getString("sp.updated.successfully");
            } else {
                message = resourceBundle.getString("sp.added.successfully");
            }
        } else {
            message = resourceBundle.getString("error.adding.sp");
        }

        if (status) {
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.INFO, request);
        } else {
            CarbonUIMessage.sendCarbonUIMessage(message, CarbonUIMessage.ERROR, request);
        }
%>
<script>
    <%
    boolean applicationComponentFound = CarbonUIUtil.isContextRegistered(config, "/application/");
    String issuerName = serviceProviderDTO.getIssuer();
    if (StringUtils.isNotBlank(serviceProviderDTO.getIssuerQualifier())){
        issuerName = SAMLSSOUIUtil.getIssuerWithQualifier(serviceProviderDTO.getIssuer(),
        serviceProviderDTO.getIssuerQualifier());
    }
    if (applicationComponentFound) {
        if (status) {
        if(attributeConsumingServiceIndex != null){
    %>
    location.href = '../application/configure-service-provider.jsp?action=update&display=samlIssuer&spName=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(spName))%>&samlIssuer=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(issuerName))%>' +
    '&attrConServIndex=<%=Encode.forJavaScriptBlock(Encode.forUriComponent(attributeConsumingServiceIndex))%>';
    <%} else {%>
    location.href = '../application/configure-service-provider.jsp?action=update&display=samlIssuer&spName=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(spName))%>&samlIssuer=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(issuerName))%>';
    <%}%>

    <% } else { if(attributeConsumingServiceIndex != null){ %>
    location.href = '../application/configure-service-provider.jsp?action=delete&display=samlIssuer&spName=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(spName))%>&samlIssuer=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(issuerName))%>&attrConServIndex=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(attributeConsumingServiceIndex))%>';

    <%}else{%>
    location.href = '../application/configure-service-provider.jsp?action=delete&display=samlIssuer&spName=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(spName))%>&samlIssuer=' +
    '<%=Encode.forJavaScriptBlock(Encode.forUriComponent(issuerName))%>';
    <%}%>
    <% } } else { %>
    location.href = 'manage_service_providers.jsp';
    <% } %>
</script>
<%

} catch (Exception e) {
    CarbonUIMessage.sendCarbonUIMessage(e.getMessage(), CarbonUIMessage.ERROR, request, e);
%>
<script type="text/javascript">
    location.href = "../admin/error.jsp";
</script>
<%
        return;
    }
%>