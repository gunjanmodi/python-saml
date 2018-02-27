# -*- coding: utf-8 -*-

""" OneLogin_Saml2_Authn_Request class

Copyright (c) 2014, OneLogin, Inc.
All rights reserved.

AuthNRequest class of OneLogin's Python Toolkit.

"""
from base64 import b64encode

from onelogin.saml2.constants import OneLogin_Saml2_Constants
from onelogin.saml2.utils import OneLogin_Saml2_Utils


class OneLogin_Saml2_Authn_Request(object):
    """

    This class handles an AuthNRequest. It builds an
    AuthNRequest object.

    """

    def __init__(self, settings, force_authn=False, is_passive=False, set_nameid_policy=True):
        """
        Constructs the AuthnRequest object.

        :param settings: OSetting data
        :type return_to: OneLogin_Saml2_Settings

        :param force_authn: Optional argument. When true the AuthNRequest will set the ForceAuthn='true'.
        :type force_authn: bool

        :param is_passive: Optional argument. When true the AuthNRequest will set the Ispassive='true'.
        :type is_passive: bool

        :param set_nameid_policy: Optional argument. When true the AuthNRequest will set a nameIdPolicy element.
        :type set_nameid_policy: bool
        """
        self.__settings = settings

        sp_data = self.__settings.get_sp_data()
        idp_data = self.__settings.get_idp_data()
        security = self.__settings.get_security_data()

        uid = OneLogin_Saml2_Utils.generate_unique_id()
        self.__id = uid
        issue_instant = OneLogin_Saml2_Utils.parse_time_to_SAML(OneLogin_Saml2_Utils.now())

        destination = idp_data['singleSignOnService']['url']

        provider_name_str = ''
        organization_data = settings.get_organization()
        if isinstance(organization_data, dict) and organization_data:
            langs = organization_data.keys()
            if 'en-US' in langs:
                lang = 'en-US'
            else:
                lang = langs[0]
            if 'displayname' in organization_data[lang] and organization_data[lang]['displayname'] is not None:
                provider_name_str = "\n" + '    ProviderName="%s"' % organization_data[lang]['displayname']

        force_authn_str = ''
        if force_authn is True:
            force_authn_str = "\n" + '    ForceAuthn="true"'

        is_passive_str = ''
        if is_passive is True:
            is_passive_str = "\n" + '    IsPassive="true"'

        nameid_policy_str = ''
        if set_nameid_policy:
            name_id_policy_format = sp_data['NameIDFormat']
            if 'wantNameIdEncrypted' in security and security['wantNameIdEncrypted']:
                name_id_policy_format = OneLogin_Saml2_Constants.NAMEID_ENCRYPTED

            nameid_policy_str = """
    <samlp:NameIDPolicy
        Format="%s"
        AllowCreate="true" />""" % name_id_policy_format

        requested_authn_context_str = ''
        if 'requestedAuthnContext' in security.keys() and security['requestedAuthnContext'] is not False:
            authn_comparison = 'exact'
            if 'requestedAuthnContextComparison' in security.keys():
                authn_comparison = security['requestedAuthnContextComparison']

            if security['requestedAuthnContext'] is True:
                requested_authn_context_str = "\n" + """    <samlp:RequestedAuthnContext Comparison="%s">
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
    </samlp:RequestedAuthnContext>""" % authn_comparison
            else:
                requested_authn_context_str = "\n" + '     <samlp:RequestedAuthnContext Comparison="%s">' % authn_comparison
                for authn_context in security['requestedAuthnContext']:
                    requested_authn_context_str += '<saml:AuthnContextClassRef>%s</saml:AuthnContextClassRef>' % authn_context
                requested_authn_context_str += '    </samlp:RequestedAuthnContext>'

        attr_consuming_service_str = ''
        if 'attributeConsumingService' in sp_data and sp_data['attributeConsumingService']:
            attr_consuming_service_str = 'AttributeConsumingServiceIndex="1"'

        certificate = sp_data["x509cert"].replace("-----BEGIN CERTIFICATE-----\n", "").replace("-----END CERTIFICATE-----", "")
        request = """<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="%(id)s"
    Version="2.0"%(provider_name)s%(force_authn_str)s%(is_passive_str)s
    IssueInstant="%(issue_instant)s"
    Destination="https://smartidqa2.paci.gov.kw/idp/SSO.saml2"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="http://api.mofa2.mykuwaitnet.net/saml?acs"
    AttributeConsumingServiceIndex="1"
    >
    <saml:Issuer>http://api.mofa2.mykuwaitnet.net/</saml:Issuer>
    <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" />
            <Reference URI="#%(id)s">
                <Transforms>
                    <Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
                    <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
                        <InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" />
                    </Transform>
                </Transforms>
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" />
                <DigestValue>4eXOfTLQRsDf3inV+aStvuCdLuo=</DigestValue>
            </Reference>
        </SignedInfo>
        <SignatureValue>ThIRfbxRUsGuAVUg3piqY8eGZ/55OqdzyLY+bOXqBsTRWbd8xAJ2YA2sTAmy0eOmNJCCDcxhRvRjSCAk1nqotv++0d8m9zshHqe4rXnBOycHvPgw55rP3lbhrhdC8yzbDVOZ0o5nisgonI1JOKUKT+ugT/4sWh/wA8+CkpJ+XCc=</SignatureValue>
        <KeyInfo>
            <X509Data>
                <X509Certificate>%(certificate)s</X509Certificate>
            </X509Data>
        </KeyInfo>
    </Signature>
    %(nameid_policy_str)s%(requested_authn_context_str)s
</samlp:AuthnRequest>""" % \
                  {
                      'id': uid,
                      'provider_name': provider_name_str,
                      'force_authn_str': force_authn_str,
                      'is_passive_str': is_passive_str,
                      'issue_instant': issue_instant,
                      'destination': destination,
                      'assertion_url': sp_data['assertionConsumerService']['url'],
                      'entity_id': sp_data['entityId'],
                      'nameid_policy_str': nameid_policy_str,
                      'requested_authn_context_str': requested_authn_context_str,
                      'attr_consuming_service_str': attr_consuming_service_str,
                      'certificate': certificate
                  }

        self.__authn_request = request

    def get_request(self, deflate=True):
        """
        Returns unsigned AuthnRequest.
        :param deflate: It makes the deflate process optional
        :type: bool
        :return: AuthnRequest maybe deflated and base64 encoded
        :rtype: str object
        """
        if deflate:
            request = OneLogin_Saml2_Utils.deflate_and_base64_encode(self.__authn_request)
        else:
            request = b64encode(self.__authn_request)
        return request

    def get_id(self):
        """
        Returns the AuthNRequest ID.
        :return: AuthNRequest ID
        :rtype: string
        """
        return self.__id

    def get_xml(self):
        """
        Returns the XML that will be sent as part of the request
        :return: XML request body
        :rtype: string
        """
        return self.__authn_request
