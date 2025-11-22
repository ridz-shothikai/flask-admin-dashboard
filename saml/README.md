# SAML Configuration

This directory contains SAML settings for Okta authentication.

## Setup Instructions

1. Copy `settings.json.example` to `settings.json`:
   ```bash
   cp saml/settings.json.example saml/settings.json
   ```

2. Update `settings.json` with your Okta configuration:
   - **sp.entityId**: Your Service Provider (SP) entity ID 
     - Example: `https://your-domain.com/api/auth/sso/metadata`
   - **sp.assertionConsumerService.url**: The ACS URL where Okta will send SAML responses
     - Example: `https://your-domain.com/api/auth/sso/acs`
     - **Note**: The actual route in this app is `/api/auth/sso/acs`
   - **idp.entityId**: Your Okta Identity Provider Issuer (paste from Okta)
   - **idp.singleSignOnService.url**: Your Okta Single Sign-On URL (paste from Okta)
   - **idp.x509cert**: Your Okta X.509 certificate (paste from Okta, remove BEGIN/END certificate lines)

## Getting Okta Configuration

**📖 See the detailed guide: [OKTA_SETUP_GUIDE.md](OKTA_SETUP_GUIDE.md)**

Quick steps:
1. Log into your Okta Admin Console
2. Navigate to Applications > Applications
3. Select your SAML application
4. Go to the "Sign On" tab
5. Find these three values:
   - **Identity Provider Issuer** → `idp.entityId`
   - **Single Sign-On URL** → `idp.singleSignOnService.url`
   - **X.509 Certificate** → `idp.x509cert` (remove BEGIN/END lines)

## Alternative: Environment Variables

You can also configure SAML settings using environment variables. The application will use hardcoded settings from `app/utils/saml_utils.py` which reads from environment variables:

- `SAML_SP_ENTITY_ID`
- `SAML_ACS_URL`
- `SAML_IDP_ENTITY_ID`
- `SAML_IDP_SSO_URL`
- `SAML_IDP_X509_CERT`

## Security Note

**DO NOT commit `settings.json` to version control** if it contains production credentials. Add it to `.gitignore`.

