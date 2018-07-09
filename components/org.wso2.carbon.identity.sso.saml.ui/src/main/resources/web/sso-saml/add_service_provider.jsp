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
<%@ page import="org.apache.axis2.AxisFault" %>
<%@ page import="org.apache.axis2.context.ConfigurationContext" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page
        import="org.wso2.carbon.CarbonConstants" %>
<%@ page import="org.wso2.carbon.CarbonError" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderInfoDTO" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOUIConstants" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.ui.client.SAMLSSOConfigServiceClient" %>
<%@ page
        import="org.wso2.carbon.security.keystore.service.CertData" %>
<%@ page
        import="org.wso2.carbon.ui.CarbonUIUtil" %>
<%@ page import="org.wso2.carbon.utils.ServerConstants" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Collections" %>
<%@ page import="java.util.List" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.context.CarbonContext" %>
<%@ page import="org.wso2.carbon.base.MultitenantConstants" %>
<%@ page import="static org.wso2.carbon.identity.sso.saml.ui.SAMLSSOUIUtil.*" %>
<%@ page import="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOUIUtil" %>


<%@ taglib prefix="fmt" uri="http://java.sun.com/jsp/jstl/fmt" %>
<%@ taglib uri="http://wso2.org/projects/carbon/taglibs/carbontags.jar" prefix="carbon" %>
<%@ taglib uri="http://www.owasp.org/index.php/Category:OWASP_CSRFGuard_Project/Owasp.CsrfGuard.tld" prefix="csrf" %>
<jsp:useBean id="samlSsoServuceProviderConfigBean"
             type="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOProviderConfigBean"
             class="org.wso2.carbon.identity.sso.saml.ui.SAMLSSOProviderConfigBean"
             scope="session"/>
<jsp:setProperty name="samlSsoServuceProviderConfigBean" property="*"/>
<jsp:include page="../dialog/display_messages.jsp"/>

<fmt:bundle
        basename="org.wso2.carbon.identity.sso.saml.ui.i18n.Resources">
    <carbon:breadcrumb label="sso.configuration"
                       resourceBundle="org.wso2.carbon.identity.sso.saml.ui.i18n.Resources"
                       topPage="true" request="<%=request%>"/>

    <script type="text/javascript" src="global-params.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/breadcrumbs.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/cookies.js"></script>
    <script type="text/javascript" src="../carbon/admin/js/main.js"></script>
    <script type="text/javascript" src="../identity/validation/js/identity-validate.js"></script>

    <script type="text/javascript">

        function doValidation() {
            var fld = document.getElementsByName("issuer")[0];
            var value = fld.value;
            if (value.length == 0) {
                CARBON.showWarningDialog(
                        "<fmt:message key='sp.enter.valid.issuer'/>", null,
                        null);
                return false;
            } else if (value.indexOf("@") > -1) {
                CARBON.showWarningDialog(
                        "<fmt:message key='sp.entity.id.cannot.have.at'/>", null,
                        null);
                return false;
            }

            var assertionConsumerURLs = null;
            if ($("#assertionConsumerURLTblRow").length) {
                assertionConsumerURLs = $('#assertionConsumerURLs').val();
            }

            if (assertionConsumerURLs == null || assertionConsumerURLs.trim().length === 0) {
                CARBON.showWarningDialog("<fmt:message key='sp.enter.valid.endpoint.address'/>", null, null);
                return false;
            }

            var defaultAssertionConsumerURL = $('#defaultAssertionConsumerURL').val();
            if (defaultAssertionConsumerURL == null || defaultAssertionConsumerURL.trim().length === 0) {
                CARBON.showWarningDialog("<fmt:message key='sp.enter.default.acs'/>", null, null);
                return false;
            }


            var fld3 = document.getElementsByName("logoutURL")[0];
            var value = fld3.value;
            var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/
            if (value.length != 0) {
                value = value.replace(/^\s+/, "");
                if (value.length != 0) {
                    if (!regexp.test(value)) {
                        CARBON.showWarningDialog(
                                "<fmt:message key='sp.enter.valid.logout.endpoint.address'/>",
                                null, null);
                        return false;
                    }
                }
            }

            return true;
        }

        function showHideTxtBox(radioBtn) {
            var claimIdRow = document.getElementById('claimIdRow');
            var nameIdRow = document.getElementById('nameIdRow');
            if (radioBtn.checked && radioBtn.value == "useClaimId") {
                claimIdRow.style.display = "";
                nameIdRow.style.display = "";
            } else {
                claimIdRow.style.display = "none";
                nameIdRow.style.display = "none";
            }
        }


        function disableLogoutUrl(chkbx) {
            if ($(chkbx).is(':checked')) {
                $("#sloResponseURL").prop('disabled', false);
                $("#sloRequestURL").prop('disabled', false);
            } else {
                $("#sloResponseURL").prop('disabled', true);
                $("#sloRequestURL").prop('disabled', true);
                $("#sloResponseURL").val("");
                $("#sloRequestURL").val("");
            }
        }

        function disableFullQualifiedUsername(chkbx) {
            document.addServiceProvider.useFullQualifiedUsername.value = (chkbx.checked) ? true
                    : false;
            document.addServiceProvider.enableNameIdClaimUriHidden.value = (chkbx.checked) ? false
                    : true;

            if (chkbx.checked) {
                document.getElementById("enableNameIdClaimUri").checked = 'false';
            }

        }
        function doValidationUrl() {
            var fld = document.getElementsByName("metadataFromUrl")[0];
            var value = fld.value;
            var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/
            if (value.length != 0) {
                value = value.replace(/^\s+/, "");
                if (value.length != 0) {
                    if (!regexp.test(value)) {
                        CARBON.showWarningDialog("<fmt:message key='sp.enter.valid.url'/>", null, null);
                        return false;
                    }
                }
            } else {
                CARBON.showWarningDialog("<fmt:message key='sp.enter.valid.url'/>", null, null);
                return false;
            }
            return true;
        }


        function disableResponseSignature(chkbx) {
            document.addServiceProvider.enableResponseSignature.value = (chkbx.checked) ? true
                    : false;
        }
        function disableAssertionSignature(chkbx) {
            document.addServiceProvider.enableAssertionSignature.value = (chkbx.checked) ? true
                    : false;
        }
        function disableAttributeProfile(chkbx) {
            if (!(chkbx.checked)) {
                document.addServiceProvider.enableDefaultAttributeProfile.checked = false;
            }
            document.addServiceProvider.enableDefaultAttributeProfile.value = chkbx.checked;
            document.addServiceProvider.enableDefaultAttributeProfile.disabled = (chkbx.checked) ? false
                    : true;

        }

        function disableNameIdClaimUri(chkbx) {
            if (chkbx.checked) {
                document.addServiceProvider.enableNameIdClaimUriHidden.value = "true";
                document.addServiceProvider.useFullQualifiedUsername.value = "false";
                document.getElementById("useFullQualifiedUsername").checked = 'false';
            } else {
                document.addServiceProvider.enableNameIdClaimUriHidden.value = "false";
            }

        }

        function disableDefaultAttributeProfile(chkbx) {
            if (chkbx.checked) {
                document.addServiceProvider.enableDefaultAttributeProfileHidden.value = "true";
            } else {
                document.addServiceProvider.enableDefaultAttributeProfileHidden.value = "false";
            }

        }
        function disableAudienceRestriction(chkbx) {
            document.addServiceProvider.audience.disabled = (chkbx.checked) ? false
                    : true;
            document.addServiceProvider.addAudience.disabled = (chkbx.checked) ? false
                    : true;
        }
        function disableRecipients(chkbx) {
            document.addServiceProvider.recipient.disabled = (chkbx.checked) ? false
                    : true;
            document.addServiceProvider.addRecipient.disabled = (chkbx.checked) ? false
                    : true;
        }

        function addAssertionConsumerURL() {

            var assertionConsumerURL = $("#assertionConsumerURLTxt").val();
            if (assertionConsumerURL == null || assertionConsumerURL.trim().length == 0) {
                CARBON.showWarningDialog("<fmt:message key='sp.enter.not.valid.endpoint.address'/>", null, null);
                return false;
            }

            assertionConsumerURL = assertionConsumerURL.trim();

            var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;
            if (!regexp.test(assertionConsumerURL) || assertionConsumerURL.indexOf(",") > -1) {
                CARBON.showWarningDialog("<fmt:message key='sp.enter.not.valid.endpoint.address'/>", null, null);
                return false;
            }

            if (!$("#assertionConsumerURLTblRow").length) {
                var row = '<tr id="assertionConsumerURLTblRow">' +
                        '    <td></td>' +
                        '    <td>' +
                        '        <table id="assertionConsumerURLsTable" style="width: 40%; margin-bottom: 3px;" class="styledInner">' +
                        '            <tbody id="assertionConsumerURLsTableBody">' +
                        '            </tbody>' +
                        '        </table>' +
                        '        <input type="hidden" id="assertionConsumerURLs" name="assertionConsumerURLs" value="">' +
                        '        <input type="hidden" id="currentColumnId" value="0">' +
                        '    </td>' +
                        '</tr>';
                $('#assertionConsumerURLInputRow').after(row);
            }

            var assertionConsumerURLs = $("#assertionConsumerURLs").val();
            var currentColumnId = $("#currentColumnId").val();
            if (assertionConsumerURLs == null || assertionConsumerURLs.trim().length == 0) {
                $("#assertionConsumerURLs").val(assertionConsumerURL);
                var row =
                        '<tr id="acsUrl_' + parseInt(currentColumnId) + '">' +
                        '</td><td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">' + assertionConsumerURL +
                        '</td><td><a onclick="removeAssertionConsumerURL (\'' + assertionConsumerURL + '\', \'acsUrl_' + parseInt(currentColumnId) + '\');return false;"' +
                        'href="#" class="icon-link" style="background-image: url(../admin/images/delete.gif)"> Delete </a></td></tr>';

                $('#assertionConsumerURLsTable tbody').append(row);
                $('#defaultAssertionConsumerURL').append($("<option></option>").attr("value", assertionConsumerURL).text(assertionConsumerURL));
                $('#defaultAssertionConsumerURL').val(assertionConsumerURL);
            } else {
                var isExist = false;
                $.each(assertionConsumerURLs.split(","), function (index, value) {
                    if (value === assertionConsumerURL) {
                        isExist = true;
                        CARBON.showWarningDialog("<fmt:message key='sp.endpoint.address.already.exists'/>", null, null);
                        return false;
                    }
                });
                if (isExist) {
                    return false;
                }

                $("#assertionConsumerURLs").val(assertionConsumerURLs + "," + assertionConsumerURL);
                var row =
                        '<tr id="acsUrl_' + parseInt(currentColumnId) + '">' +
                        '</td><td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">' + assertionConsumerURL +
                        '</td><td><a onclick="removeAssertionConsumerURL(\'' + assertionConsumerURL + '\', \'acsUrl_' + parseInt(currentColumnId) + '\');return false;"' +
                        'href="#" class="icon-link" style="background-image: url(../admin/images/delete.gif)"> Delete </a></td></tr>';

                $('#assertionConsumerURLsTable tr:last').after(row);
                $('#defaultAssertionConsumerURL').append($("<option></option>").attr("value", assertionConsumerURL).text(assertionConsumerURL));
            }
            $("#assertionConsumerURLTxt").val("");
            $("#currentColumnId").val(parseInt(currentColumnId) + 1);
        }

        function onClickAddACRUrl() {
            var isValidated = doValidateInputToConfirm(document.getElementById('assertionConsumerURLTxt'), "<fmt:message key='sp.not.https.endpoint.address'/>",
                    addAssertionConsumerURL, null, null);
            if (isValidated) {
                addAssertionConsumerURL();
            }
        }

        function removeAssertionConsumerURL(assertionConsumerURL, columnId) {

            var assertionConsumerURLs = $("#assertionConsumerURLs").val();
            var defaultAssertionConsumerURL = $('#defaultAssertionConsumerURL').val();
            var newAssertionConsumerURLs = "";
            var isDeletingSelected = false;

            if (assertionConsumerURLs != null && assertionConsumerURLs.trim().length > 0) {
                $.each(assertionConsumerURLs.split(","), function (index, value) {
                    if (value === assertionConsumerURL) {
                        if (assertionConsumerURL === defaultAssertionConsumerURL) {
                            isDeletingSelected = true;
                        }
                        return true;
                    }

                    if (newAssertionConsumerURLs.length > 0) {
                        newAssertionConsumerURLs = newAssertionConsumerURLs + "," + value;
                    } else {
                        newAssertionConsumerURLs = value;
                    }
                });
            }

            $('#defaultAssertionConsumerURL option[value="' + assertionConsumerURL + '"]').remove();

            if (isDeletingSelected && newAssertionConsumerURLs.length > 0) {
                $('select[id="defaultAssertionConsumerURL"] option:eq(1)').attr('selected', 'selected');
            }

            $('#' + columnId).remove();
            $("#assertionConsumerURLs").val(newAssertionConsumerURLs);

            if (newAssertionConsumerURLs.length == 0) {
                $('#assertionConsumerURLTblRow').remove();
            }
        }

        function addSloReturnToURL() {

            var returnToURL = $("#returnToURLTxtBox").val();
            if (returnToURL == null || returnToURL.trim().length == 0) {
                CARBON.showWarningDialog("<fmt:message key='slo.enter.not.valid.endpoint.address'/>", null, null);
                return false;
            }

            returnToURL = returnToURL.trim();

            var regexp = /(ftp|http|https):\/\/(\w+:{0,1}\w*@)?(\S+)(:[0-9]+)?(\/|\/([\w#!:.?+=&%@!\-\/]))?/;
            if (!regexp.test(returnToURL) || returnToURL.indexOf(",") > -1) {
                CARBON.showWarningDialog("<fmt:message key='slo.enter.not.valid.endpoint.address'/>", null, null);
                return false;
            }

            if (!$("#idpSLOReturnToURLsTblRow").length) {
                var row = '<tr id="idpSLOReturnToURLsTblRow">' +
                        '    <td></td>' +
                        '    <td>' +
                        '        <table id="idpSLOReturnToURLsTbl" style="width: 40%; margin-bottom: 3px;" class="styledInner">' +
                        '            <tbody id="idpSLOReturnToURLsTblBody">' +
                        '            </tbody>' +
                        '        </table>' +
                        '        <input type="hidden" id="idpInitSLOReturnToURLs" name="idpInitSLOReturnToURLs" value="">' +
                        '        <input type="hidden" id="currentReturnToColumnId" value="0">' +
                        '    </td>' +
                        '</tr>';
                $('#idpSLOReturnToURLInputRow').after(row);
            }

            var idpInitSLOReturnToURLs = $("#idpInitSLOReturnToURLs").val();
            var currentColumnId = $("#currentReturnToColumnId").val();
            if (idpInitSLOReturnToURLs == null || idpInitSLOReturnToURLs.trim().length == 0) {
                $("#idpInitSLOReturnToURLs").val(returnToURL);
                var row =
                        '<tr id="returnToUrl_' + parseInt(currentColumnId) + '">' +
                        '</td><td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">' + returnToURL +
                        '</td><td><a onclick="removeSloReturnToURL(\'' + returnToURL + '\', \'returnToUrl_' +
                        parseInt(currentColumnId) + '\');return false;"' +
                        'href="#" class="icon-link" style="background-image: url(../admin/images/delete.gif)"> Delete </a></td></tr>';

                $('#idpSLOReturnToURLsTbl tbody').append(row);
            } else {
                var isExist = false;
                $.each(idpInitSLOReturnToURLs.split(","), function (index, value) {
                    if (value === returnToURL) {
                        isExist = true;
                        CARBON.showWarningDialog("<fmt:message key='slo.endpoint.address.already.exists'/>", null, null);
                        return false;
                    }
                });
                if (isExist) {
                    return false;
                }

                $("#idpInitSLOReturnToURLs").val(idpInitSLOReturnToURLs + "," + returnToURL);
                var row =
                        '<tr id="returnToUrl_' + parseInt(currentColumnId) + '">' +
                        '</td><td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">' +
                        returnToURL + '</td><td><a onclick="removeSloReturnToURL(\'' + returnToURL + '\', \'returnToUrl_' + parseInt(currentColumnId) + '\');return false;"' +
                        'href="#" class="icon-link" style="background-image: url(../admin/images/delete.gif)"> Delete </a></td></tr>';

                $('#idpSLOReturnToURLsTbl tr:last').after(row);
            }
            $("#returnToURLTxtBox").val("");
            $("#currentReturnToColumnId").val(parseInt(currentColumnId) + 1);
        }

        function removeSloReturnToURL(returnToURL, columnId) {

            var idpInitSLOReturnToURLs = $("#idpInitSLOReturnToURLs").val();
            var newIdpInitSLOReturnToURLs = "";

            if (idpInitSLOReturnToURLs != null && idpInitSLOReturnToURLs.trim().length > 0) {
                $.each(idpInitSLOReturnToURLs.split(","), function (index, value) {
                    if (value === returnToURL) {
                        return true;
                    }

                    if (newIdpInitSLOReturnToURLs.length > 0) {
                        newIdpInitSLOReturnToURLs = newIdpInitSLOReturnToURLs + "," + value;
                    } else {
                        newIdpInitSLOReturnToURLs = value;
                    }
                });
            }

            $('#' + columnId).remove();
            $("#idpInitSLOReturnToURLs").val(newIdpInitSLOReturnToURLs);

            if (newIdpInitSLOReturnToURLs.length == 0) {
                $('#idpSLOReturnToURLsTblRow').remove();
            }
        }

        function disableIdPInitSLO(chkbx) {
            if ($(chkbx).is(':checked')) {
                $("#returnToURLTxtBox").prop('disabled', false);
                $("#addReturnToURL").prop('disabled', false);
            } else {
                $("#returnToURLTxtBox").prop('disabled', true);
                $("#addReturnToURL").prop('disabled', true);
            }
        }

        function addClaim() {
            var propertyCount = document.getElementById("claimPropertyCounter");

            var i = propertyCount.value;
            var currentCount = parseInt(i);

            currentCount = currentCount + 1;
            propertyCount.value = currentCount;

            document.getElementById('claimTableId').style.display = '';
            var claimTableTBody = document.getElementById('claimTableTbody');

            var claimRow = document.createElement('tr');
            claimRow.setAttribute('id', 'claimRow' + i);

            var claim = document.getElementById('claim').value;
            var claimPropertyTD = document.createElement('td');
            claimPropertyTD.setAttribute('style', 'padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;');
            claimPropertyTD.innerHTML = "" + claim + "<input type='hidden' name='claimPropertyName" + i + "' id='claimPropertyName" + i + "'  value='" + claim + "'/> ";

            var claimRemoveTD = document.createElement('td');
            claimRemoveTD.innerHTML = "<a href='#' class='icon-link' style='background-image: url(../admin/images/delete.gif)' onclick='removeClaim(" + i + ");return false;'>" + "Delete" + "</a>";

            claimRow.appendChild(claimPropertyTD);
            claimRow.appendChild(claimRemoveTD);

            claimTableTBody.appendChild(claimRow);
        }
        function addAudienceFunc() {
            var propertyCount = document.getElementById("audiencePropertyCounter");

            var i = propertyCount.value;
            var currentCount = parseInt(i);

            currentCount = currentCount + 1;
            propertyCount.value = currentCount;

            document.getElementById('audienceTableId').style.display = '';
            var audienceTableTBody = document.getElementById('audienceTableTbody');

            var audienceRow = document.createElement('tr');
            audienceRow.setAttribute('id', 'audienceRow' + i);

            var audience = document.getElementById('audience').value;
            var audiencePropertyTD = document.createElement('td');
            audiencePropertyTD.setAttribute('style', 'padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;');
            audiencePropertyTD.innerHTML = "" + audience + "<input type='hidden' name='audiencePropertyName" + i + "' id='audiencePropertyName" + i + "'  value='" + audience + "'/> ";

            var audienceRemoveTD = document.createElement('td');
            audienceRemoveTD.innerHTML = "<a href='#' class='icon-link' style='background-image: url(../admin/images/delete.gif)' onclick='removeAudience(" + i + ");return false;'>" + "Delete" + "</a>";

            audienceRow.appendChild(audiencePropertyTD);
            audienceRow.appendChild(audienceRemoveTD);

            audienceTableTBody.appendChild(audienceRow);
        }
        function addRecipientFunc() {
            var propertyCount = document.getElementById("recipientPropertyCounter");

            var i = propertyCount.value;
            var currentCount = parseInt(i);

            currentCount = currentCount + 1;
            propertyCount.value = currentCount;

            document.getElementById('recipientTableId').style.display = '';
            var recipientTableTBody = document.getElementById('recipientTableTbody');

            var recipientRow = document.createElement('tr');
            recipientRow.setAttribute('id', 'recipientRow' + i);

            var recipient = document.getElementById('recipient').value;
            var recipientPropertyTD = document.createElement('td');
            recipientPropertyTD.setAttribute('style', 'padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;');
            recipientPropertyTD.innerHTML = "" + recipient + "<input type='hidden' name='recipientPropertyName" + i + "' id='recipientPropertyName" + i + "'  value='" + recipient + "'/> ";

            var recipientRemoveTD = document.createElement('td');
            recipientRemoveTD.innerHTML = "<a href='#' class='icon-link' style='background-image: url(../admin/images/delete.gif)' onclick='removeRecipient(" + i + ");return false;'>" + "Delete" + "</a>";

            recipientRow.appendChild(recipientPropertyTD);
            recipientRow.appendChild(recipientRemoveTD);

            recipientTableTBody.appendChild(recipientRow);
        }

        function removeClaim(i) {
            var propRow = document.getElementById("claimRow" + i);
            if (propRow != undefined && propRow != null) {
                var parentTBody = propRow.parentNode;
                if (parentTBody != undefined && parentTBody != null) {
                    parentTBody.removeChild(propRow);
                    if (!isContainRaw(parentTBody)) {
                        var propertyTable = document.getElementById("claimTableId");
                        propertyTable.style.display = "none";

                    }
                }
            }
        }

        function removeAudience(i) {
            var propRow = document.getElementById("audienceRow" + i);
            if (propRow != undefined && propRow != null) {
                var parentTBody = propRow.parentNode;
                if (parentTBody != undefined && parentTBody != null) {
                    parentTBody.removeChild(propRow);
                    if (!isContainRaw(parentTBody)) {
                        var propertyTable = document.getElementById("audienceTableId");
                        propertyTable.style.display = "none";
                    }
                }
            }
        }

        function removeRecipient(i) {
            var propRow = document.getElementById("recipientRow" + i);
            if (propRow != undefined && propRow != null) {
                var parentTBody = propRow.parentNode;
                if (parentTBody != undefined && parentTBody != null) {
                    parentTBody.removeChild(propRow);
                    if (!isContainRaw(parentTBody)) {
                        var propertyTable = document.getElementById("recipientTableId");
                        propertyTable.style.display = "none";
                    }
                }
            }
        }

        function disableIdPInitSSO(chkbx) {
            document.addServiceProvider.disableIdPInitSSO.value = (chkbx.checked) ? true
                    : false;
        }

        function isContainRaw(tbody) {
            if (tbody.childNodes == null || tbody.childNodes.length == 0) {
                return false;
            } else {
                for (var i = 0; i < tbody.childNodes.length; i++) {
                    var child = tbody.childNodes[i];
                    if (child != undefined && child != null) {
                        if (child.nodeName == "tr" || child.nodeName == "TR") {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        function clearAll() {
            document.addServiceProvider.action = "update_claims.jsp?action=clear&spName=<%=Encode.forUriComponent(request.getParameter("spName"))%>";
            document.addServiceProvider.submit();
        }
    </script>

    <%
        String cookie;
        String serverURL;
        ConfigurationContext configContext;
        SAMLSSOConfigServiceClient spConfigClient = (SAMLSSOConfigServiceClient) session.getAttribute(SAMLSSOUIConstants.CONFIG_CLIENT);
        List<String> aliasSet = null;
        String[] claimUris = null;
        String configPath = null;
        CertData certData = null;

        String applicationSPName = request.getParameter("spName");
        session.setAttribute("application-sp-name", applicationSPName);

        SAMLSSOServiceProviderInfoDTO serviceProviderInfoDTO = null;
        ArrayList<SAMLSSOServiceProviderDTO> providers =
                new ArrayList<SAMLSSOServiceProviderDTO>();
        String reload = null;

        try {
            reload = request.getParameter("reload");
            serverURL = CarbonUIUtil.getServerURL(config.getServletContext(), session);
            configContext =
                    (ConfigurationContext) config.getServletContext()
                            .getAttribute(CarbonConstants.CONFIGURATION_CONTEXT);
            cookie = (String) session.getAttribute(ServerConstants.ADMIN_SERVICE_COOKIE);

            if (spConfigClient == null) {

                spConfigClient =
                        new SAMLSSOConfigServiceClient(cookie, serverURL,
                                configContext);
                if (spConfigClient.getRegisteredServiceProviders().getServiceProviders() != null) {
                    session.setAttribute(SAMLSSOUIConstants.CONFIG_CLIENT, spConfigClient);
                }

            }

            serviceProviderInfoDTO = spConfigClient.getRegisteredServiceProviders();
            if (serviceProviderInfoDTO.getServiceProviders() != null) {

                Collections.addAll(providers, serviceProviderInfoDTO.getServiceProviders());
            }
            aliasSet = spConfigClient.getCertAlias();
            claimUris = spConfigClient.getClaimURIs();
        } catch (AxisFault e) {
            CarbonError error = new CarbonError();
            error.addError(e.getMessage());
            request.getSession().setAttribute(CarbonError.ID, error);
    %>
    <script type="text/javascript">
        location.href = '../admin/error.jsp';
    </script>
    <%
        }
    %>

    <div id="middle">
        <h2>
            <fmt:message key="saml.sso.register.service.provider"/>
        </h2>
        <div id="workArea">
            <%
                SAMLSSOServiceProviderDTO provider = null;
                String spAction = request.getParameter("SPAction");
                String claimTableStyle = "display:none";
                String audienceTableStyle = "display:none";
                String recipientTableStyle = "display:none";
                String issuer = request.getParameter("issuer");
                String attributeConsumingServiceIndex = "";
                boolean isEditSP = false;
                if (spAction != null && "editServiceProvider".equals(spAction)) {
                    if (providers.size() > 0) {
                        for (SAMLSSOServiceProviderDTO sp : providers) {
                            if (issuer.equals(sp.getIssuer())) {
                                isEditSP = true;
                                provider = sp;
                                if (provider.getRequestedClaims() != null) {
                                    claimTableStyle = provider.getRequestedClaims().length > 0 ? "" : "display:none";
                                }
                                if (provider.getRequestedAudiences() != null) {
                                    audienceTableStyle = provider.getRequestedAudiences().length > 0 ? "" : "display:none";
                                }
                                if (provider.getRequestedRecipients() != null) {
                                    recipientTableStyle = provider.getRequestedRecipients().length > 0 ? "" : "display:none";
                                }
                                if (provider.getAttributeConsumingServiceIndex() != null) {
                                    attributeConsumingServiceIndex = provider.getAttributeConsumingServiceIndex();
                                }
                                if (provider.getAttributeConsumingServiceIndex() != null) {
                                    attributeConsumingServiceIndex = provider.getAttributeConsumingServiceIndex();
                                }
                            }
                        }
                    }
                }

            %>
            <%
                if (!isEditSP) {
            %>


            <table class="styledLeft" width="100%">
                <thead>
                <tr>
                    <th><fmt:message key="sp.select.mode"/></th>
                </tr>
                </thead>
                <tbody>
                <tr>
                    <td><input type="radio" id="manual-option" name="upload-type-selector" checked="checked"
                            onclick="showManual();">
                        <label for="manual-option">Manual Configuration</label></td>

                </tr>
                <tr>
                    <td>
                        <input type="radio" id="file-option" name="upload-type-selector" onclick="showFile();">
                        <label for="file-option">Metadata File Configuration</label></td>
                </tr>

                <tr>
                    <td>
                        <input type="radio" id="url-option" name="upload-type-selector" onclick="showURL();">
                        <label for="url-option">URL Configuration</label>
                </tr>
                </tbody>
            </table>
            <br/>

            <%
                }
            %>
            <form method="POST"
                  action="add_service_provider_finish-ajaxprocessor.jsp?SPAction=<%=Encode.forUriComponent(spAction)%>"
                  id="addServiceProvider" name="addServiceProvider" target="_self"
                  onsubmit="return doValidation();">
                <table class="styledLeft" width="100%">
                    <thead>
                    <tr>
                        <%
                            if (isEditSP) {
                        %>
                        <th><fmt:message key="saml.sso.edit.service.provider"/>

                        </th>
                        <%
                        } else {
                        %>
                        <th><fmt:message key="saml.sso.new.service.provider"/></th>
                        <%
                            }
                        %>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td class="formRow">
                            <table class="normal" cellspacing="0" style="width: 100%;">
                                <tr>
                                    <td style="width: 300px;" title="Unique identifier of the service provider specified in the SAML Authentication Request">
                                        <fmt:message key="sp.issuer"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td><input type="text" id="issuer" name="issuer" maxlength="100"
                                               class="text-box-big"
                                               value="<%=isEditSP? Encode.forHtmlAttribute(provider.getIssuer()):""%>" <%=isEditSP ? "disabled=\"disabled\"" : ""%>/>
                                        <input type="hidden" id="hiddenIssuer" name="hiddenIssuer"
                                               value="<%=isEditSP? Encode.forHtmlAttribute(provider.getIssuer()):""%>"/>
                                    </td>
                                </tr>
                                <tr id="assertionConsumerURLInputRow">
                                    <td title="URL to which the browser should be redirected to after the authentication is successful">
                                        <fmt:message key="sp.assertionConsumerURLs"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <input type="text" id="assertionConsumerURLTxt" class="text-box-big" value=""
                                               white-list-patterns="https-url"/>
                                        <input id="addAssertionConsumerURLBtn" type="button"
                                               value="<fmt:message key="saml.sso.add.acs"/>"
                                               onclick="onClickAddACRUrl()"/>
                                    </td>
                                </tr>
                                <%
                                    if (isEditSP && provider.getAssertionConsumerUrls() != null) {
                                %>
                                <tr id="assertionConsumerURLTblRow">
                                    <td></td>
                                    <td>
                                        <table id="assertionConsumerURLsTable" style="width: 40%; margin-bottom: 3px;"
                                               class="styledInner">
                                            <tbody id="assertionConsumerURLsTableBody">
                                            <%
                                                StringBuilder assertionConsumerURLsBuilder = new StringBuilder();
                                                int acsColumnId = 0;
                                                for (String assertionConsumerURL : provider.getAssertionConsumerUrls()) {
                                                    if (assertionConsumerURLsBuilder.length() > 0) {
                                                        assertionConsumerURLsBuilder.append(",").append(assertionConsumerURL);
                                                    } else {
                                                        assertionConsumerURLsBuilder.append(assertionConsumerURL);
                                                    }
                                            %>
                                            <tr id="acsUrl_<%=acsColumnId%>">
                                                <td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">
                                                    <%=Encode.forHtml(assertionConsumerURL)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeAssertionConsumerURL('<%=Encode.forJavaScriptAttribute(assertionConsumerURL)%>',
                                                            'acsUrl_<%=acsColumnId%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">
                                                        Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                    acsColumnId++;
                                                }
                                            %>
                                            </tbody>
                                        </table>
                                        <input type="hidden" id="assertionConsumerURLs" name="assertionConsumerURLs"
                                               value="<%=assertionConsumerURLsBuilder.length() > 0 ?
         Encode.forHtmlAttribute(assertionConsumerURLsBuilder.toString()) : ""%>">
                                        <input type="hidden" id="currentColumnId" value="<%=acsColumnId%>">
                                    </td>
                                </tr>
                                <%
                                    }
                                %>

                                <tr id="defaultAssertionConsumerURLRow">
                                    <td title="Default Assertion Consumer URL in case you are unable to retrieve it from the authentication request">
                                        <fmt:message key="sp.defaultAssertionConsumerURL"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <select id="defaultAssertionConsumerURL" name="defaultAssertionConsumerURL">
                                            <option value="">---Select---</option>
                                            <%
                                                if (isEditSP && provider.getAssertionConsumerUrls() != null) {
                                                    for (String assertionConsumerUrl : provider.getAssertionConsumerUrls()) {
                                                        if (assertionConsumerUrl.equals(provider.getDefaultAssertionConsumerUrl())) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(assertionConsumerUrl)%>" selected>
                                                <%=Encode.forHtmlContent(assertionConsumerUrl)%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(assertionConsumerUrl)%>">
                                                <%=Encode.forHtmlContent(assertionConsumerUrl)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>

                                <!-- NameID format -->

                                <tr>
                                    <td title="Defines the name identifier formats supported by the identity provider">
                                        <fmt:message key="sp.nameIDFormat"/>
                                    </td>
                                    <td>
                                        <input type="text" id="nameIdFormat"
                                               name="nameIdFormat" class="text-box-big"
                                               value="<%=isEditSP? Encode.forHtmlAttribute(provider.getNameIDFormat().replace("/", ":")):"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"%>"/>
                                    </td>
                                </tr>

                                <% if (applicationSPName == null || applicationSPName.isEmpty()) { %>

                                <!-- UseUserClaimValueInNameID -->

                                <% if (isEditSP && provider.getNameIdClaimUri() != null) {
                                %>
                                <tr>
                                    <td colspan="2">
                                        <input type="checkbox"
                                               name="enableNameIdClaimUri" value="true" checked="checked"
                                               onclick="disableNameIdClaimUri(this);"/>
                                        <input type="hidden" id="enableNameIdClaimUriHidden"
                                               name="enableNameIdClaimUriHidden" value="true"/>

                                        <fmt:message
                                                key='define.nameid'/>
                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <select id="nameIdClaim" name="nameIdClaim">
                                            <%
                                                if (claimUris != null) {
                                                    for (String claimUri : claimUris) {
                                                        if (claimUri != null) {
                                                            if (claimUri.equals(provider.getNameIdClaimUri())) {

                                            %>
                                            <option selected="selected" value="<%=Encode.forHtmlAttribute(claimUri)%>">
                                                <%=Encode.forHtmlContent(claimUri)%>
                                            </option>
                                            <% } else { %>
                                            <option value="<%=Encode.forHtmlAttribute(claimUri)%>"><%=Encode.forHtmlContent(claimUri)%>
                                            </option>
                                            <%
                                                            }
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2">
                                        <input type="checkbox"
                                               name="enableNameIdClaimUri" value="true"
                                               onclick="disableNameIdClaimUri(this);"/>
                                        <fmt:message
                                                key='define.nameid'/>
                                        <input type="hidden" id="enableNameIdClaimUriHidden"
                                               name="enableNameIdClaimUriHidden"/>

                                    </td>
                                </tr>
                                <tr>
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <select id="nameIdClaim" name="nameIdClaim">
                                            <%
                                                if (claimUris != null) {
                                                    for (String claimUri : claimUris) {
                                                        if (claimUri != null) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(claimUri)%>"><%=Encode.forHtmlContent(claimUri)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>
                                <% }
                                }%>

                                <!-- Certificate Alias -->

                                <% if (isEditSP) {
                                %>
                                <tr>
                                    <td title="Used to validate the signature of SAML2 requests and is used to generate encryption">
                                        <fmt:message key="sp.certAlias"/>
                                    </td>
                                    <td>
                                        <select id="alias" name="alias">
                                            <%
                                                if (aliasSet != null) {
                                                    boolean isDefaultAliasSet = false;
                                                    for (String alias : aliasSet) {
                                                        if (alias != null && alias.equals(provider.getCertAlias())) {
                                                            isDefaultAliasSet = true;
                                            %>
                                                            <option selected="selected"
                                                                 value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        } else if (alias != null && !isDefaultAliasSet && alias.equals(SAMLSSOUIConstants.DEFAULT_CERTIFICATE_ALIAS)) {
                                            %>
                                                            <option selected="selected"
                                                                value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        } else {
                                            %>
                                                            <option value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select></td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td title="Used to validate the signature of SAML2 requests and is used to generate encryption">
                                        <fmt:message key="sp.certAlias"/>
                                    </td>
                                    <td>
                                        <select id="alias" name="alias">
                                            <%
                                                if (aliasSet != null) {
                                                    boolean isDefaultAliasSet = false;
                                                    for (String alias : aliasSet) {
                                                        if (alias != null && alias.equals(samlSsoServuceProviderConfigBean.getCertificateAlias())) {
                                                            isDefaultAliasSet = true;
                                            %>
                                                            <option selected="selected"
                                                                value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        } else if (alias != null && !isDefaultAliasSet && alias.equals(SAMLSSOUIConstants.DEFAULT_CERTIFICATE_ALIAS)) {
                                            %>
                                                            <option selected="selected"
                                                                value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        } else {
                                            %>
                                                            <option value="<%=Encode.forHtmlAttribute(alias)%>"><%=Encode.forHtmlContent(alias)%>
                                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select></td>
                                </tr>
                                <%}%>


                                <!--selectResponseSignAlgo-->
                                <tr id="defaultSigningAlgorithmRow">
                                    <td title="Specifies the SignatureMethod algorithm to be used in the Signature element in POST binding">
                                        <fmt:message key="sp.signingAlgorithm"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <select id="signingAlgorithm" name="signingAlgorithm">
                                            <%
                                                if (spConfigClient.getSigningAlgorithmUris() != null) {
                                                    for (String signingAlgo : spConfigClient.getSigningAlgorithmUris()) {
                                                        String signAlgorithm = null;
                                                        if (provider != null) {
                                                            signAlgorithm = provider.getSigningAlgorithmURI();
                                                        } else {
                                                            signAlgorithm = spConfigClient.getSigningAlgorithmUriByConfig();
                                                        }
                                                        if (signAlgorithm != null && signingAlgo.equals(signAlgorithm)) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(signingAlgo)%>" selected>
                                                <%=Encode.forHtml(signingAlgo)%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(signingAlgo)%>">
                                                <%=Encode.forHtml(signingAlgo)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>

                                <!--digestAlgorithmRow-->
                                <tr id="digestAlgorithmRow">
                                    <td title="Specifies the DigestMethod algorithm to be used in the Signature element in POST binding">
                                        <fmt:message key="sp.digestAlgorithm"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <select id="digestAlgorithm" name="digestAlgorithm">
                                            <%
                                                if (spConfigClient.getDigestAlgorithmURIs() != null) {
                                                    for (String digestAlgo : spConfigClient.getDigestAlgorithmURIs()) {
                                                        String digestAlgorithm = null;
                                                        if (provider != null) {
                                                            digestAlgorithm = provider.getDigestAlgorithmURI();
                                                        } else {
                                                            digestAlgorithm = spConfigClient.getDigestAlgorithmURIByConfig();
                                                        }
                                                        if (digestAlgorithm != null && digestAlgo.equals(digestAlgorithm)) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(digestAlgo)%>" selected>
                                                <%=Encode.forHtml(digestAlgo)%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(digestAlgo)%>">
                                                <%=Encode.forHtml(digestAlgo)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>

                                <!--assertionEncryptionAlgorithmRow-->
                                <tr id="assertionEncryptionAlgorithmRow">
                                    <td>
                                        <fmt:message key="sp.assertionEncryptionAlgorithm"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <select id="assertionEncryptionAlgorithm" name="assertionEncryptionAlgorithm">
                                            <%
                                                if (spConfigClient.getAssertionEncryptionAlgorithmURIs() != null) {
                                                    for (String assertionEncryptionAlgo : spConfigClient.getAssertionEncryptionAlgorithmURIs()) {
                                                        String assertionEncryptionAlgorithm = null;
                                                        if (provider != null) {
                                                            assertionEncryptionAlgorithm = provider.getAssertionEncryptionAlgorithmURI();
                                                        } else {
                                                            assertionEncryptionAlgorithm = spConfigClient.getAssertionEncryptionAlgorithmURIByConfig();
                                                        }
                                                        if (assertionEncryptionAlgorithm != null && assertionEncryptionAlgo.equals(assertionEncryptionAlgorithm)) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(assertionEncryptionAlgo)%>" selected>
                                                <%=Encode.forHtml(assertionEncryptionAlgo)%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(assertionEncryptionAlgo)%>">
                                                <%=Encode.forHtml(assertionEncryptionAlgo)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>

                                <!--keyEncryptionAlgorithmRow-->
                                <tr id="keyEncryptionAlgorithmRow">
                                    <td>
                                        <fmt:message key="sp.keyEncryptionAlgorithm"/>
                                        <font color="red">*</font>
                                    </td>
                                    <td>
                                        <select id="keyEncryptionAlgorithm" name="keyEncryptionAlgorithm">
                                            <%
                                                if (spConfigClient.getKeyEncryptionAlgorithmURIs() != null) {
                                                    for (String keyEncryptionAlgo : spConfigClient.getKeyEncryptionAlgorithmURIs()) {
                                                        String keyEncryptionAlgorithm = null;
                                                        if (provider != null) {
                                                            keyEncryptionAlgorithm = provider.getKeyEncryptionAlgorithmURI();
                                                        } else {
                                                            keyEncryptionAlgorithm = spConfigClient.getKeyEncryptionAlgorithmURIByConfig();
                                                        }
                                                        if (keyEncryptionAlgorithm != null && keyEncryptionAlgo.equals(keyEncryptionAlgorithm)) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(keyEncryptionAlgo)%>" selected>
                                                <%=Encode.forHtml(keyEncryptionAlgo)%>
                                            </option>
                                            <%
                                            } else {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(keyEncryptionAlgo)%>">
                                                <%=Encode.forHtml(keyEncryptionAlgo)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select>
                                    </td>
                                </tr>

                                <tr>
                                    <td colspan="2" title="Select Enable Response Signing to sign the SAML2 Responses returned after the authentication process">
                                        <input type="checkbox" name="enableResponseSignature" value="true"
                                               onclick="disableResponseSignature(this);"
                                                <%=(isResponseSigningEnabled(isEditSP, provider) ? "checked" : "")%> />
                                        <fmt:message key="do.response.signature"/>
                                    </td>
                                </tr>

                                <input type="hidden" name="enableAssertionSignature" value="true"/>

                                <!-- enableSigValidation -->
                                <%
                                    if (isSignatureValidationEnabledForRequests(isEditSP, provider)) {
                                %>
                                <tr>
                                    <td colspan="2" title="This specifies whether the identity provider must validate the signature of the SAML2 authentication request">
                                        <input type="checkbox" id="enableSigValidation"
                                               name="enableSigValidation" value="true" checked="checked"/>
                                        <fmt:message
                                                key='validate.signature'/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="This specifies whether the identity provider must validate the signature of the SAML2 authentication request">
                                        <input type="checkbox" id="enableSigValidation"
                                               name="enableSigValidation" value="true"/>
                                        <fmt:message
                                                key='validate.signature'/>
                                    </td>
                                </tr>
                                <%}%>

                                <!-- Enable Encrypted assertion -->
                                <% if (isEditSP && provider.isDoEnableEncryptedAssertionSpecified() && provider.getDoEnableEncryptedAssertion()) {
                                %>
                                <tr>
                                    <td colspan="2" title="Enable Assertion Encryption, if you wish to encrypt the assertion">
                                        <input type="checkbox" id="enableEncAssertion"
                                               name="enableEncAssertion" value="true" checked="checked"/>
                                        <fmt:message
                                                key='encrypted.assertion'/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Enable Assertion Encryption, if you wish to encrypt the assertion">
                                        <input type="checkbox" id="enableEncAssertion"
                                               name="enableEncAssertion" value="true"/>
                                        <fmt:message
                                                key='encrypted.assertion'/>
                                    </td>
                                </tr>
                                <%}%>

                                <!-- EnableSingleLogout -->
                                <tr>
                                    <td colspan="2" title="Enable Single Logout so that all sessions are terminated once the user signs out from one server">
                                    <input type="checkbox"
                                                           name="enableSingleLogout" value="true"
                                                           onclick="disableLogoutUrl(this);"
                                            <%= isSingleLogoutEnabled(isEditSP, provider) ? "checked" : ""%>/>
                                        <fmt:message
                                                key="enable.single.logout"/></td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="slo.response.url"/>
                                    </td>
                                    <td><input type="text" id="sloResponseURL" name="sloResponseURL"
                                               value="<%=(isEditSP && StringUtils.isNotBlank(provider.getSloResponseURL())) ?
               Encode.forHtmlAttribute(provider.getSloResponseURL()) : ""%>"
                                               class="text-box-big" <%=(isEditSP && provider.getDoSingleLogout()) ? "" : "disabled=\"disabled\""%>>
                                        <div class="sectionHelp" style="margin-top: 2px;">
                                            Single logout response accepting endpoint
                                        </div>
                                    </td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="slo.request.url"/>
                                    </td>
                                    <td><input type="text" id="sloRequestURL" name="sloRequestURL"
                                               value="<%=(isEditSP && StringUtils.isNotBlank(provider.getSloRequestURL())) ?
               Encode.forHtmlAttribute(provider.getSloRequestURL()) : ""%>"
                                               class="text-box-big" <%=(isEditSP && provider.getDoSingleLogout()) ? "" : "disabled=\"disabled\""%>>
                                        <div class="sectionHelp" style="margin-top: 2px;">
                                            Single logout request accepting endpoint
                                        </div>
                                    </td>
                                </tr>
                                <!-- EnableAttributeProfile -->
                                <%
                                    boolean show = false;
                                    if (applicationSPName == null || applicationSPName.isEmpty()) {
                                        show = provider.getRequestedClaims() != null && provider.getRequestedClaims().length > 0 &&
                                                provider.getRequestedClaims()[0] != null;
                                    } else {
                                        show = true;
                                    }

                                    if (isEditSP && show) {
                                %>
                                <tr>
                                    <td colspan="2" title="Select Enable Attribute Profile to enable this and add a claim by entering the claim link and clicking the Add Claim button">
                                        <% if (SAMLSSOUIUtil.isAttributeProfileEnabled(isEditSP, provider)) {%>
                                        <input type="checkbox"
                                               name="enableAttributeProfile" id="enableAttributeProfile" value="true"
                                               onclick="disableAttributeProfile(this);" checked/>
                                        <% } else { %>
                                        <input type="checkbox"
                                               name="enableAttributeProfile" id="enableAttributeProfile"
                                               onclick="disableAttributeProfile(this);"/>
                                        <% } %>
                                        <fmt:message
                                                key="enable.attribute.profile"/></td>
                                </tr>
                                <% if (applicationSPName == null || applicationSPName.isEmpty()) { %>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.claim"/>
                                    </td>
                                    <td>
                                        <select id="claim" name="claim">
                                            <%
                                                if (claimUris != null) {
                                                    for (String claimUri : claimUris) {
                                                        if (claimUri != null) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(claimUri)%>"><%=Encode.forHtmlContent(claimUri)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select> <input id="addClaims" name="addClaims" type="button"
                                                         value="<fmt:message key="saml.sso.add.claim"/>"
                                                         onclick="addClaim()"/>
                                    </td>
                                </tr>
                                <% } %>
                                <tr>
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;"
                                        colspan="2">
                                        <% if (StringUtils.isNotEmpty(provider.getAttributeConsumingServiceIndex())) {
                                            if (provider.getEnableAttributesByDefault()) {
                                        %> <input type="checkbox"
                                                  name="enableDefaultAttributeProfile"
                                                  id="enableDefaultAttributeProfile" checked="checked" value="true"
                                                  onclick="disableDefaultAttributeProfile(this);"/>
                                        <input type="hidden" id="enableDefaultAttributeProfileHidden"
                                               name="enableDefaultAttributeProfileHidden"
                                               value="true"/>
                                        <%} else {%>
                                        <input type="checkbox"
                                               name="enableDefaultAttributeProfile" id="enableDefaultAttributeProfile"
                                               onclick="disableDefaultAttributeProfile(this);"/>
                                        <input type="hidden" id="enableDefaultAttributeProfileHidden"
                                               name="enableDefaultAttributeProfileHidden"
                                        />
                                        <% }
                                        } else {%>
                                        <input type="hidden" id="enableDefaultAttributeProfileHidden"
                                               name="enableDefaultAttributeProfileHidden"/>
                                        <input type="checkbox"
                                               name="enableDefaultAttributeProfile" id="enableDefaultAttributeProfile"
                                               disabled="disabled"
                                               onclick="disableDefaultAttributeProfile(this);"/>
                                        <% } %>
                                        <fmt:message key="enable.default.attribute.profile"/>
                                    </td>
                                </tr>

                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Select Enable Attribute Profile to enable this and add a claim by entering the claim link and clicking the Add Claim button">
                                        <input type="checkbox"
                                               name="enableAttributeProfile" id="enableAttributeProfile" value="true"
                                               onclick="disableAttributeProfile(this);"/>
                                        <fmt:message key="enable.attribute.profile"/>
                                    </td>
                                </tr>
                                <% if (applicationSPName == null || applicationSPName.isEmpty()) { %>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.claim"/>
                                    </td>
                                    <td>
                                        <select id="claim" name="claim" disabled="disabled">
                                            <%
                                                if (claimUris != null) {
                                                    for (String claimUri : claimUris) {
                                                        if (claimUri != null) {
                                            %>
                                            <option value="<%=Encode.forHtmlAttribute(claimUri)%>"><%=Encode.forHtmlContent(claimUri)%>
                                            </option>
                                            <%
                                                        }
                                                    }
                                                }
                                            %>
                                        </select> <input id="addClaims" name="addClaims" type="button"
                                                         disabled="disabled"
                                                         value="<fmt:message key="saml.sso.add.claim"/>"
                                                         onclick="addClaim()"/>
                                    </td>
                                </tr>
                                <% } %>
                                <tr>
                                    <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;"
                                        colspan="2">
                                        <input type="hidden" id="enableDefaultAttributeProfileHidden"
                                               name="enableDefaultAttributeProfileHidden"/>
                                        <input type="checkbox"
                                               name="enableDefaultAttributeProfile" id="enableDefaultAttributeProfile"
                                               onclick="disableDefaultAttributeProfile(this);"/>
                                        <fmt:message key="enable.default.attribute.profile"/>
                                    </td>
                                </tr>

                                <%} %>
                                <tr>
                                    <td>
                                        <table id="claimTableId" style="<%=claimTableStyle%>" class="styledInner">
                                            <tbody id="claimTableTbody">
                                            <%
                                                int i = 0;
                                                if (isEditSP && provider.getRequestedClaims() != null && provider.getRequestedClaims().length > 0) {
                                            %>
                                            <%
                                                for (String claim : provider.getRequestedClaims()) {
                                                    if (claim != null && !"null".equals(claim)) {
                                            %>
                                            <tr id="claimRow<%=i%>">
                                                <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                                    <input type="hidden" name="claimPropertyName<%=i%>"
                                                           id="claimPropertyName<%=i%>"
                                                           value="<%=Encode.forHtmlAttribute(claim)%>"/><%=Encode.forHtml(claim)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeClaim('<%=i%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                        i++;
                                                    }
                                                }
                                            %>
                                            <%
                                                }
                                            %>
                                            <input type="hidden" name="claimPropertyCounter" id="claimPropertyCounter"
                                                   value="<%=i%>"/>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>

                                <!-- EnableAudienceRestriction -->
                                <% if (isEditSP && provider.getRequestedAudiences() != null && provider.getRequestedAudiences().length > 0 &&
                                        provider.getRequestedAudiences()[0] != null) {
                                %>
                                <tr>
                                    <td title="Enable Audience Restriction to restrict the audience. You may add audience members using the Audience text box and clicking the Add button" colspan="2"><input type="checkbox"
                                                           name="enableAudienceRestriction"
                                                           id="enableAudienceRestriction"
                                                           value="true" checked="checked"
                                                           onclick="disableAudienceRestriction(this);"/> <fmt:message
                                            key="enable.audience.restriction"/></td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.audience"/>
                                    </td>
                                    <td>
                                        <input type="text" id="audience" name="audience"
                                               class="text-box-big"/>
                                        <input id="addAudience" name="addAudience" type="button"
                                               value="<fmt:message key="saml.sso.add.audience"/>"
                                               onclick="addAudienceFunc()"/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Enable Audience Restriction to restrict the audience. You may add audience members using the Audience text box and clicking the Add button">
                                        <input type="checkbox"
                                               name="enableAudienceRestriction" id="enableAudienceRestriction"
                                               value="true"
                                               onclick="disableAudienceRestriction(this);"/>
                                        <fmt:message key="enable.audience.restriction"/>
                                    </td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.audience"/>
                                    </td>
                                    <td>
                                        <input type="text" id="audience" name="audience"
                                               class="text-box-big" disabled="disabled"/>
                                        <input id="addAudience" name="addAudience" type="button"
                                               disabled="disabled" value="<fmt:message key="saml.sso.add.audience"/>"
                                               onclick="addAudienceFunc()"/>
                                    </td>
                                </tr>
                                <%} %>
                                <tr>
                                    <td></td>
                                    <td>
                                        <table id="audienceTableId" style="width: 40%; <%=audienceTableStyle%>"
                                               class="styledInner">
                                            <tbody id="audienceTableTbody">
                                            <%
                                                int j = 0;
                                                if (isEditSP && provider.getRequestedAudiences() != null && provider.getRequestedAudiences().length >
                                                        0) {
                                            %>
                                            <%
                                                for (String audience : provider.getRequestedAudiences()) {
                                                    if (audience != null && !"null".equals(audience)) {
                                            %>
                                            <tr id="audienceRow<%=j%>">
                                                <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                                    <input type="hidden" name="audiencePropertyName<%=j%>"
                                                           id="audiencePropertyName<%=j%>"
                                                           value="<%=Encode.forHtmlAttribute(audience)%>"/>
                                                    <%=Encode.forHtml(audience)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeAudience('<%=j%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                        j++;
                                                    }
                                                }
                                            %>
                                            <%
                                                }
                                            %>
                                            <input type="hidden" name="audiencePropertyCounter"
                                                   id="audiencePropertyCounter"
                                                   value="<%=j%>"/>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>

                                <!-- EnableRecipientValidation -->
                                <% if (isEditSP && provider.getRequestedRecipients() != null && provider.getRequestedRecipients().length > 0 &&
                                        provider.getRequestedRecipients()[0] != null) {
                                %>
                                <tr>
                                    <td title="Select this if you require validation from the recipient of the response" colspan="2"><input type="checkbox"
                                                           name="enableRecipients" id="enableRecipients"
                                                           value="true" checked="checked"
                                                           onclick="disableRecipients(this);"/> <fmt:message
                                            key="enable.recipient.validation"/></td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.recipient"/>
                                    </td>
                                    <td>
                                        <input type="text" id="recipient" name="recipient"
                                               class="text-box-big"/>
                                        <input id="addRecipient" name="addRecipient" type="button"
                                               value="<fmt:message key="saml.sso.add.recipient"/>"
                                               onclick="addRecipientFunc()"/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Select this if you require validation from the recipient of the response">
                                        <input type="checkbox"
                                               name="enableRecipients" id="enableRecipients" value="true"
                                               onclick="disableRecipients(this);"/>
                                        <fmt:message key="enable.recipient.validation"/>
                                    </td>
                                </tr>
                                <tr>
                                    <td
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.recipient"/>
                                    </td>
                                    <td>
                                        <input type="text" id="recipient" name="recipient"
                                               class="text-box-big" disabled="disabled"/>
                                        <input id="addRecipient" name="addRecipient" type="button"
                                               disabled="disabled" value="<fmt:message key="saml.sso.add.recipient"/>"
                                               onclick="addRecipientFunc()"/>
                                    </td>
                                </tr>
                                <%} %>
                                <tr>
                                    <td></td>
                                    <td>
                                        <table id="recipientTableId" style="width: 40%; <%=recipientTableStyle%>"
                                               class="styledInner">
                                            <tbody id="recipientTableTbody">
                                            <%
                                                int k = 0;
                                                if (isEditSP && provider.getRequestedRecipients() != null && provider.getRequestedRecipients().length >
                                                        0) {
                                            %>
                                            <%
                                                for (String recipient : provider.getRequestedRecipients()) {
                                                    if (recipient != null && !"null".equals(recipient)) {
                                            %>
                                            <tr id="recipientRow<%=k%>">
                                                <td style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                                    <input type="hidden" name="recipientPropertyName<%=k%>"
                                                           id="recipientPropertyName<%=k%>"
                                                           value="<%=Encode.forHtmlAttribute(recipient)%>"/><%=Encode.forHtml(recipient)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeRecipient('<%=k%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                        k++;
                                                    }
                                                }
                                            %>
                                            <%
                                                }
                                            %>
                                            <input type="hidden" name="recipientPropertyCounter"
                                                   id="recipientPropertyCounter"
                                                   value="<%=k%>"/>
                                            </tbody>
                                        </table>
                                    </td>
                                </tr>

                                <!-- IdP-Initiated SSO -->
                                <tr>
                                    <td colspan="2" title="Select the Enable IdP Initiated SSO checkbox to enable this functionality. When this is enabled, the service provider is not required to send the SAML2 request">
                                        <input type="checkbox" name="enableIdPInitSSO" value="true"
                                               onclick="disableIdPInitSSO(this);"
                                                <%=(isEditSP && provider.getIdPInitSSOEnabled() ? "checked=\"checked\"" : "")%> />
                                        <fmt:message key="enable.idp.init.sso"/>
                                    </td>
                                </tr>

                                <!-- IdP-Initiated SLO -->
                                <tr>
                                    <td colspan="2">
                                        <input type="checkbox" name="enableIdPInitSLO" value="true"
                                               onclick="disableIdPInitSLO(this);"
                                                <%=(isEditSP && provider.getIdPInitSLOEnabled() ? "checked=\"checked\"" : "")%> />
                                        <fmt:message key="enable.idp.init.slo"/>
                                    </td>
                                </tr>


                                <tr id="idpSLOReturnToURLInputRow">
                                    <td title="Select the Enable IdP Initiated SLO checkbox to enable this functionality. You must specify the URL"
                                            style="padding-left: 40px ! important; color: rgb(119, 119, 119); font-style: italic;">
                                        <fmt:message key="sp.returnTo.url"/>
                                    </td>
                                    <td>
                                        <input type="text" id="returnToURLTxtBox" class="text-box-big" <%=(isEditSP &&
                                                provider.getIdPInitSLOEnabled()) ? "" : "disabled=\"disabled\""%> />
                                        <input id="addReturnToURL"
                                               type="button" <%=(isEditSP && provider.getIdPInitSLOEnabled()) ? "" : "disabled=\"disabled\""%>
                                               value="<fmt:message key="saml.sso.add.returnTo"/>"
                                               onclick="addSloReturnToURL()"/>
                                    </td>
                                </tr>

                                <%
                                    if (isEditSP && provider.getIdpInitSLOReturnToURLs() != null) {
                                %>
                                <tr id="idpSLOReturnToURLsTblRow">
                                    <td></td>
                                    <td title="Select the Enable IdP Initiated SLO checkbox to enable this functionality. You must specify the URL">
                                        <table id="idpSLOReturnToURLsTbl" style="width: 40%;" class="styledInner">
                                            <tbody id="idpSLOReturnToURLsTblBody">
                                            <%
                                                StringBuilder sloReturnToURLsBuilder = new StringBuilder();
                                                int returnToColumnId = 0;
                                                for (String returnToURL : provider.getIdpInitSLOReturnToURLs()) {
                                                    if (returnToURL != null && !"null".equals(returnToURL)) {
                                                        if (sloReturnToURLsBuilder.length() > 0) {
                                                            sloReturnToURLsBuilder.append(",").append(returnToURL);
                                                        } else {
                                                            sloReturnToURLsBuilder.append(returnToURL);
                                                        }
                                            %>
                                            <tr id="returnToUrl_<%=returnToColumnId%>">
                                                <td style="padding-left: 15px !important; color: rgb(119, 119, 119);font-style: italic;">
                                                    <%=Encode.forHtml(returnToURL)%>
                                                </td>
                                                <td>
                                                    <a onclick="removeSloReturnToURL('<%=Encode.forJavaScriptAttribute(Encode.forUri(returnToURL))%>', 'returnToUrl_<%=returnToColumnId%>');return false;"
                                                       href="#" class="icon-link"
                                                       style="background-image: url(../admin/images/delete.gif)">
                                                        Delete
                                                    </a>
                                                </td>
                                            </tr>
                                            <%
                                                        returnToColumnId++;
                                                    }
                                                }
                                            %>
                                            </tbody>
                                        </table>
                                        <input type="hidden" id="idpInitSLOReturnToURLs" name="idpInitSLOReturnToURLs"
                                               value="<%=sloReturnToURLsBuilder.length() > 0 ?
         Encode.forHtmlAttribute(sloReturnToURLsBuilder.toString()) : ""%>">
                                        <input type="hidden" id="currentReturnToColumnId" value="<%=returnToColumnId%>">
                                    </td>
                                </tr>
                                <%
                                    }
                                %>

                                <tr><td></td></tr>

                                <!-- Enable Attribute Query Profile -->
                                <% if (isEditSP && provider.isAssertionQueryRequestProfileEnabledSpecified() &&
                                        provider.getAssertionQueryRequestProfileEnabled()) {
                                %>
                                <tr>
                                    <td colspan="2" title="Used for query assertions following SAML2.0 specification">
                                        <input type="checkbox" id="enableAssertionQueryRequestProfile"
                                               name="enableAssertionQueryRequestProfile" value="true" checked="checked"/>
                                        <fmt:message key='sp.enable.assertion.query.request.profile'/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Used for query assertions following SAML2.0 specification">
                                        <input type="checkbox" id="enableAssertionQueryRequestProfile"
                                               name="enableAssertionQueryRequestProfile" value="true"/>
                                        <fmt:message key='sp.enable.assertion.query.request.profile'/>
                                    </td>
                                </tr>
                                <%}%>

                                <!-- Enable SAML2 Artifact Binding -->
                                <% if (isEditSP && provider.getEnableSAML2ArtifactBinding()) {
                                %>
                                <tr>
                                    <td colspan="2" title="Used for artifact binding following SAML2.0 specification">
                                        <input type="checkbox" id="enableSAML2ArtifactBinding"
                                               name="enableSAML2ArtifactBinding" value="true" checked="checked"/>
                                        <fmt:message key='sp.enable.saml2.artifact.binding'/>
                                    </td>
                                </tr>
                                <% } else {%>
                                <tr>
                                    <td colspan="2" title="Used for artifact binding following SAML2.0 specification">
                                        <input type="checkbox" id="enableSAML2ArtifactBinding"
                                               name="enableSAML2ArtifactBinding" value="true"/>
                                        <fmt:message key='sp.enable.saml2.artifact.binding'/>
                                    </td>
                                </tr>
                                <%}%>

                            </table>
                        </td>
                    </tr>
                    <tr>
                        <td class="buttonRow">
                            <%
                                if (isEditSP) {
                            %>
                            <input class="button" type="submit" value="<fmt:message key="saml.sso.edit"/>"/>
                            <%
                            } else {
                            %>
                            <input class="button" type="submit" value="<fmt:message key="saml.sso.register"/>"/>
                            <%
                                }
                            %>
                            <input class="button" type="button" onclick="clearAll()"
                                   value="<fmt:message key="saml.sso.cancel"/>"/>
                        </td>
                    </tr>
                    </tbody>
                </table>
                <input type="hidden" id="attributeConsumingServiceIndex" name="attributeConsumingServiceIndex"
                       value="<%=Encode.forHtmlAttribute(attributeConsumingServiceIndex)%>"/>
            </form>

            <%
                if (!isEditSP) {
            %>
            <form method="POST" action="../../fileupload/service?<csrf:tokenname/>=<csrf:tokenvalue/>"
                  id="uploadServiceProvider" name="uploadServiceProvider" target="_self" enctype="multipart/form-data"
                  onsubmit="return doValidation();">

                <table class="styledLeft" width="100%">
                    <thead>
                    <tr>
                        <th><fmt:message key="saml.sso.upload.service.provider.metadata"/></th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td><span>File Location: </span><input type="file" id="metadataFromFileSystem"
                                                               name="metadataFromFileSystem" size="50"/></td>
                    </tr>
                    <tr>
                        <td>
                            <input type="button" value="<fmt:message key='saml.sso.upload'/>" class="button"
                                   onclick="doSubmit();"/>
                            <input class="button" type="reset" value="<fmt:message key='saml.sso.cancel'/>"
                                   onclick="doCancel();"/></td>
                    </tr>
                    </tbody>
                </table>
            </form>

            <form method="POST"
                  action="upload_service_provider_from_url_finish.jsp?SPAction=<%=spAction%>"
                  id="uploadServiceProviderFromUrl" name="uploadServiceProviderFromUrl" target="_self"
                  onsubmit="return doValidationUrl();">

                <table class="styledLeft" width="100%">
                    <thead>
                    <tr>
                        <th><fmt:message key="saml.sso.upload.service.provider.metadata.from.url"/></th>
                    </tr>
                    </thead>
                    <tbody>
                    <tr>
                        <td><span>URL: </span><input type="url" class="text-box-big" id="metadataFromUrl"
                                                     name="metadataFromUrl"/></td>
                    </tr>
                    <tr>
                        <td>
                            <input type="submit" class="button" value="<fmt:message key='saml.sso.upload'/>"
                                   class="button"/ >
                            <input class="button" type="reset" value="<fmt:message key='saml.sso.cancel'/>"
                                   onclick="doCancel();"/></td>
                    </tr>
                    </tbody>
                </table>
            </form>
            <%
                }
            %>

            <script type="text/javascript">
                function showManual() {
                    $("#addServiceProvider").show();
                    $("#uploadServiceProvider").hide();
                    $("#uploadServiceProviderFromUrl").hide();
                }
                function showFile() {
                    $("#addServiceProvider").hide();
                    $("#uploadServiceProvider").show();
                    $("#uploadServiceProviderFromUrl").hide();
                }
                function showURL() {
                    $("#addServiceProvider").hide();
                    $("#uploadServiceProvider").hide();
                    $("#uploadServiceProviderFromUrl").show();
                }
                showManual();

            </script>

            <script type="text/javascript">

                function doSubmit() {
                    var policy;
                    policy = document.uploadServiceProvider.metadataFromFileSystem.value;

                    if (policy == '') {
                        CARBON.showWarningDialog("<fmt:message key='sp.metadata.valid.file'/>");
                        return;
                    }
                    document.uploadServiceProvider.submit();
                }

                function doCancel() {
                    document.getElementById("metadataFromFileSystem").value = "";

                }

            </script>
            <script type="text/javascript">
                
                // Update the certificate alias list down accessibility according to the enable signature validation
                // check box.
                $(document).ready(function () {
                    var enableSigValidation = $("#enableSigValidation");
                    var enableAssertionEnc = $("#enableEncAssertion");
                    updateCertificateAliasListAccess(enableSigValidation.is(':checked') || enableAssertionEnc.is(':checked'));
                    enableSigValidation.change(function () {
                        updateCertificateAliasListAccess(this.checked || enableAssertionEnc.is(':checked'));
                    })
                    enableAssertionEnc.change(function () {
                        updateCertificateAliasListAccess(this.checked || enableSigValidation.is(':checked'));
                    })
                });
                
                function updateCertificateAliasListAccess(enable) {
                    if (enable) {
                        $("#alias").prop('disabled', false);
                    } else {
                        $("#alias").prop('disabled', 'disabled');
                    }
                }
    
            </script>
        </div>

    </div>
</fmt:bundle>
