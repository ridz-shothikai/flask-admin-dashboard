"""SAML utility functions for Okta authentication"""
import os
import json
import logging
from flask import request

logger = logging.getLogger(__name__)


def prepare_flask_request(request_obj):
    """
    Prepare Flask request for SAML processing
    Converts Flask request to format expected by python3-saml
    """
    url_data = request_obj.url
    return {
        'https': 'on' if request_obj.scheme == 'https' else 'off',
        'http_host': request_obj.host,
        'server_port': request_obj.environ.get('SERVER_PORT', ''),
        'script_name': request_obj.path,
        'get_data': request_obj.args.copy(),
        'post_data': request_obj.form.copy(),
        'query_string': request_obj.query_string.decode('utf-8') if request_obj.query_string else '',
        'request_uri': request_obj.path + ('?' + request_obj.query_string.decode('utf-8') if request_obj.query_string else '')
    }


def load_saml_settings_from_json():
    """Load SAML settings from the settings.json file"""
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        saml_settings_path = os.path.join(current_dir, '..', '..', 'saml', 'settings.json')
        
        if not os.path.exists(saml_settings_path):
            saml_settings_path = os.path.join(os.getcwd(), 'saml', 'settings.json')
        
        logger.info(f"Looking for SAML settings at: {saml_settings_path}")
        
        if os.path.exists(saml_settings_path):
            with open(saml_settings_path, 'r') as f:
                settings = json.load(f)
                logger.info("SAML settings loaded from JSON file")
                return settings
        else:
            logger.warning(f"SAML settings file not found at: {saml_settings_path}")
            return None
            
    except Exception as e:
        logger.error(f"Error loading SAML settings: {e}")
        return None


def get_saml_settings():
    """
    Get hardcoded SAML settings as fallback
    These should be configured via environment variables or settings.json
    """
    return {
        'strict': False,  # Changed from True to False for more lenient validation
        'debug': True,
        "sp": {
            "entityId": os.getenv("SAML_SP_ENTITY_ID", "https://intellidocfinder-dfcsffs.dhs.ga.gov/backend/api/v1/auth/metadata/"),
            "assertionConsumerService": {
                "url": os.getenv("SAML_ACS_URL", "https://intellidocfinder-dfcsffs.dhs.ga.gov/backend/api/v1/auth/sso/acs"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
            },
        },
        "idp": {
            "entityId": os.getenv("SAML_IDP_ENTITY_ID", "http://www.okta.com/exk1lkg6mwaAZpE3P358"),
            "singleSignOnService": {
                "url": os.getenv("SAML_IDP_SSO_URL", "https://connect.gets.ga.gov/app/gets_dhsdfcs_1/exk1lkg6mwaAZpE3P358/sso/saml"),
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
            },
            "x509cert": os.getenv("SAML_IDP_X509_CERT", "MIIDmDCCAoCgAwIBAgIGAZfCBneWMA0GCSqGSIb3DQEBCwUAMIGMMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxDTALBgNVBAMMBGdldHMxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjUwNjMwMTgwNzEzWhcNMzUwNjMwMTgwODEyWjCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMQ0wCwYDVQQDDARnZXRzMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkIBjRzquU8HgTagxUKSHCR1HRHD79YoWnosHulbX6s6/VQgSYMBijkF/5ym8AvS90ovaSE27iAYbJIdBUsbO4o2VU4htCR4mcPvWAx+PvTVUCGT7ykOJqaGWOreQvF63oZpQA6Po8INuEwc86RPk6gPlBrKRzpRzgglLLKoMnaLD7XO+UaBxze6eMX0MEBSQwkQhuoYaXD/VqEnq9C/qVyTkhLAtUyhdG0WRsqhW1LW0U8ZmFKOmb7P1ljkWHXb4HlMtPGkq5l4UFny6AymlKlzimtc3IVAf/3Is9vzfz3BwT+61qkcXaufkN0RqrblH7kOtyneInfk6k3GJlrJ+RQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQArvWJu4fk33eB5taCpOatxj4K+BsQddu9VQlOSyVdcKcW4I5tHnwi4+hhQhn+mmQ+opyW0xygeJTXQ6Vls39ykXOsDbKVqykGdCDY+GCQQ+gnU4Glsw93rNd+IVdnH7szzr3n8kBisEqBXir1p4mwX2UgoGyWmru2+1buQCTi8iRMeID0DdbnVoVKZfRyFnqqqv1NwDg77FJDLkjJUmXeainu78xaXoGoUQtlUPu1x9cm/cvZuiS3Xr8zmbJRGyEoGA/8MfudFYoyErWe8sSwKKr6QXwyGtRch1rj8JAG7PkRA3p339J7FHnhof2645d/YXauQx505vZwaHdo0f8qN")
        },
        'security': {
            'nameIdEncrypted': False,
            'authnRequestsSigned': False,
            'logoutRequestsSigned': False,
            'logoutResponsesSigned': False,
            'signMetadata': False,
            'wantAssertionsSigned': False,
            'wantMessagesSigned': False,
            'wantNameId': True,
            'wantNameIdEncrypted': False,
            'wantAssertionsEncrypted': False,
            'allowRepeatAttributeName': False,
            'rejectUnsolicitedResponsesWithInResponseTo': False,
            'signatureAlgorithm': 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
            'digestAlgorithm': 'http://www.w3.org/2001/04/xmlenc#sha256',
        }
    }

