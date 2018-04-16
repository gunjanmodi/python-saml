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

        # destination = idp_data['singleSignOnService']['url']
        #destination = 'https://fed.paci.gov.kw/idp/SSO.saml2'
        destination = 'https://smartidqa2.paci.gov.kw/'
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

        certificate = "MIIDqzCCApKgAwIBAgIBADANBgkqhkiG9w0BAQ0FADBvMQswCQYDVQQGEwJrdzEPMA0GA1UECAwGS3V3YWl0MSQwIgYDVQQKDBtNaW5pc3RyeSBvZiBGb3JlaWduIEFmZmFpcnMxKTAnBgNVBAMMIGh0dHBzOi8vYXBpLmRldi5haWQubW9mYS5nb3Yua3cvMB4XDTE4MDQwMjA3MTM0MloXDTI4MDMzMDA3MTM0MlowbzELMAkGA1UEBhMCa3cxDzANBgNVBAgMBkt1d2FpdDEkMCIGA1UECgwbTWluaXN0cnkgb2YgRm9yZWlnbiBBZmZhaXJzMSkwJwYDVQQDDCBodHRwczovL2FwaS5kZXYuYWlkLm1vZmEuZ292Lmt3LzCCASMwDQYJKoZIhvcNAQEBBQADggEQADCCAQsCggECAM0iMD7x+k44+WJlRwoBSp9WA7maFhaGLZl0bK44aYZ9HRK7LdTJdkbBlDb3csQHgGzoPZliFj+Zp7NS0VWpi1r5qu4cWzhUjUWzRck7Kb3pL/v/n4ipzx+5jo9S5MRE+aGXJJ7NnaR84D5q9LQC3vt9bUj+ar4mpbYu+20IN0MkyKlnn+1YZF9oXZ9k3IrSsOUbeyXswM2ICmowxfLj9zaXYQM7CX6XB9KTThSplr62AgayXCjVLmhPhhZXMxZ+d/H4wdX+mDYcA+v+UfCa+tmywn0A3DsgiBMm1iHOo9jJou4Q/6rebU0PcEf5m4/dz/WdSxtiirDlGdNdJ4xqoeHTAgMBAAGjUDBOMB0GA1UdDgQWBBQC+/qFWLrqp7LWVLqgS4ud/pin5zAfBgNVHSMEGDAWgBQC+/qFWLrqp7LWVLqgS4ud/pin5zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBDQUAA4IBAgCwpKemu0QnnzkTyNs/o3mZqgMxxJopXHmzLYECAsGoN6901Wnj0NinGPCl1K7MSGhtGeu2yieQx0cDExLhOEdlu9LPwYjp2iZ7Nv/dxpEz3RyJAcnaf+vI2A8dBUI9eFRQzefPIWOcEVY/qaTuqQVUgGoi+1qfNADhqKHyQdqhgPy7tulaUaXuW2WHnjcEjyy8G6wqbvfcLXmSl2akXh29ICUErKm8PT5n7FNefQGmg8AuvSEnfH+NB06/Qcqy5x6+Lw/OOJo0DkR3CghhMgA/jqpnhO3LgT+dG+gIREl1rWMCiX/8xwomWpIcEAksWSL5ZKasUSKf6wpnHJoeiaMyGQ==",
        privateKey = "MIIEwQIBADANBgkqhkiG9w0BAQEFAASCBKswggSnAgEAAoIBAgDNIjA+8fpOOPliZUcKAUqfVgO5mhYWhi2ZdGyuOGmGfR0Suy3UyXZGwZQ293LEB4Bs6D2ZYhY/maezUtFVqYta+aruHFs4VI1Fs0XJOym96S/7/5+Iqc8fuY6PUuTERPmhlySezZ2kfOA+avS0At77fW1I/mq+JqW2LvttCDdDJMipZ5/tWGRfaF2fZNyK0rDlG3sl7MDNiApqMMXy4/c2l2EDOwl+lwfSk04UqZa+tgIGslwo1S5oT4YWVzMWfnfx+MHV/pg2HAPr/lHwmvrZssJ9ANw7IIgTJtYhzqPYyaLuEP+q3m1ND3BH+ZuP3c/1nUsbYoqw5RnTXSeMaqHh0wIDAQABAoIBAQ+Fmb75kmYe24f9f92a8WmTGZ8OsMMtjf/BloOsUxfRGcUUEsi6IdACz9NE8BMzOh2DiT209VgEqXLhPmPL+3Z709pGnQRrKXFvukUay/LJ1U6tLgYqSzjsUoQ30oWjbnwysputlVMf+9vdPfztBrBi8kUGs08GH53kejPq3jufZ7+BumqDvDo8hRJcSfEmFr7sVDRm4rWAmZ0SUcZbJrED49czXNlN2qG1ypeJoppIcmUShx+DdV+wNTbsoIGoUE2wg26jch7FW9UQYF3X4VZXAGO7JCIv0ODA0DrwiRZ9ozvjO7TiLL5kSeJgIYlBiZVmxG+z4U2ju9zIFP/9zhchAoGBD1Ab7fSr6/9PpiyBN6Jbe+bPIRfYiLfDS2zHoqUa9S59Wh9YzHGKPGDRpSGExKm74pAmN8GsvSN7M8KGCvMZISdjKSqDBPTU7lJRxhHP8rF8yA7kLhRws1POwD3gcph03n9+LaXgE+e/8MldrnP/MgasPkwU3aV6utf5iumhVCJxAoGBDWVnDz3++kLW1E/5J81coF6FLrSPO1E4/uqfjorOyYwSjInKYs4Ig2aVgaW/ru5Byu3NIDgmlv94IJt6dYHFxfzf+rHWs+veNM+BoAstKJCtz1alzH0bW+tlCzeSggpY6VDDQ5WzJz2B3j2dUxi3fqcdjsXkQsbo0n0EouDmNWKDAoGBAULh6gmbF4ch8lf8FK8ExgHO0bT7Gte3+EBveRAMVmGL5Z5rW/uGHU8ENYu7Oc+ZMCIbY8BKEBIaFbtR+xjm2vo5iqx7ui7IUxDot13EOQMxefDwDnOUjNC8WM0/7XBtP95UcEIXYMxX3OdZFgNr45z1FvSBS3hT0Yv0e+KebSWhAoGBC53WW/pX5K8XWi8rkV9dJlgwx8qdtkN92FifGl22akJER4ipbzrZWREZLr8L1OcZOJ80VO88T46jnisVa1aoqULa+6tB0u4D1+nlr2Jhu56SiozJ4+TNV81t5uc+7fOJHHIDkdT78Vg+CPmHNurlHDhQwmFKyrlwZi8xWQkLuFl/AoGBA4oEP/ubLakCMfzeF00MUzKq0rIerRH8Iy9ATlvV9uhw5VPys1MCVHWo4FkBeekc9lYt+FTaFhpgDmIUB9xdmA8X9WyWR4gAT3stlORhPxy33/6/GaYFhFY7yAy7GiL+0J9vn8tag2hFjrGG+yrxqpKb9jNkNNr1AMMPx5fiPJva"
        # signature_value = 'owbA6nJRn8TMQojq27rkqMBk+z2s8Fly1F68MEMd1InH6vFpVQqvwn7NrEP7YEJnTiHH3y8vrQvpHqBYuXoJjoZpjLdmV3jlprrzjDF+ZFUeqqfUO9h8JAVPTtxwrIEj0bfzH76pCU9h+Fu0kEekQ0UjKGHUEOZbd1+W7lmcc7U='
        assertion__consumer_service_url = 'https://api.dev.aid.mofa.gov.kw/saml?acs'
        # digest_value = 'Eph2yJzbGPhlVQThAl1OHWF/bmM='
        saml_issuer = 'https://api.dev.aid.mofa.gov.kw/'
        request = """<samlp:AuthnRequest ID="%(id)s" Version="2.0" IssueInstant="%(issue_instant)s" Destination="%(destination)s" ForceAuthn="false" IsPassive="false" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AssertionConsumerServiceURL="%(assertion__consumer_service_url)s" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">%(saml_issuer)s</saml:Issuer><Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignedInfo><CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" /><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1" /><Reference URI="#%(id)s"><Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" /><Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"><InclusiveNamespaces PrefixList="#default samlp saml ds xs xsi" xmlns="http://www.w3.org/2001/10/xml-exc-c14n#" /></Transform></Transforms><DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1" /></Reference></SignedInfo><KeyInfo><X509Data><X509Certificate>%(certificate)s</X509Certificate></X509Data></KeyInfo></Signature><samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true" /></samlp:AuthnRequest>""" % \
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
                      'certificate': certificate,
                      'assertion__consumer_service_url': assertion__consumer_service_url,
                      'saml_issuer':saml_issuer
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
