# How to Get Your Okta SAML Configuration Values

This guide will help you get the three required values from Okta to complete your `settings.json` file.

## Step 1: Log into Okta Admin Console

1. Go to your Okta Admin Console (usually `https://your-company.okta.com`)
2. Sign in with your admin credentials

## Step 2: Navigate to Your SAML Application

1. In the Okta Admin Console, click on **Applications** in the left sidebar
2. Click on **Applications** (or **Browse App Catalog** if you haven't created the app yet)
3. Find and click on your SAML application (or create a new one)

## Step 3: Get the Identity Provider Issuer

1. Click on the **Sign On** tab of your SAML application
2. Scroll down to find the **SAML 2.0** section
3. Look for **Identity Provider Issuer** or **Issuer**
4. Copy this value - it will look something like:
   - `http://www.okta.com/exk1lkg6mwaAZpE3P358`
   - Or your custom domain like `https://your-company.okta.com`

**Paste this value into `settings.json` as `idp.entityId`**

## Step 4: Get the Single Sign-On URL

1. Still in the **Sign On** tab, look for **Single Sign-On URL** or **SSO URL**
2. It will be in the same **SAML 2.0** section
3. Copy this URL - it will look something like:
   - `https://your-company.okta.com/app/your-app-name/exk1lkg6mwaAZpE3P358/sso/saml`
   - Or `https://connect.gets.ga.gov/app/gets_dhsdfcs_1/exk1lkg6mwaAZpE3P358/sso/saml`

**Paste this value into `settings.json` as `idp.singleSignOnService.url`**

## Step 5: Get the X.509 Certificate

1. Still in the **Sign On** tab, scroll to the **SAML Signing Certificates** section
2. You'll see one or more certificates listed
3. Click on the **Actions** button (three dots) next to the certificate
4. Select **View IdP metadata** or **View Certificate**
5. You'll see the certificate in this format:
   ```
   -----BEGIN CERTIFICATE-----
   MIIDmDCCAoCgAwIBAgIGAZfCBneWMA0GCSqGSIb3DQEBCwUAMIGMMQswCQYDVQQG
   ... (many lines of base64 encoded text) ...
   -----END CERTIFICATE-----
   ```
6. **IMPORTANT**: Copy ONLY the base64 text between the BEGIN and END lines
   - Remove the `-----BEGIN CERTIFICATE-----` line
   - Remove the `-----END CERTIFICATE-----` line
   - Remove all line breaks and spaces
   - You should have one continuous string of characters

**Alternative method**: 
- Click **View IdP metadata** and look for the `<X509Certificate>` tag in the XML
- Copy the content inside that tag (it's already the base64 string without BEGIN/END)

**Paste this value into `settings.json` as `idp.x509cert`**

## Step 6: Configure Okta Application Settings

In your Okta application, you also need to configure:

1. Go to the **General** tab
2. Click **Edit** in the **App Settings** section
3. Set the following:

   **Single Sign-On URL (ACS URL)**:
   ```
   http://127.0.0.1:5000/api/auth/sso/acs
   ```
   (For production, use your actual domain: `https://your-domain.com/api/auth/sso/acs`)

   **Audience URI (SP Entity ID)**:
   ```
   http://127.0.0.1:5000/api/auth/sso/metadata
   ```
   (For production: `https://your-domain.com/api/auth/sso/metadata`)

4. **Name ID format**: Usually `EmailAddress` or `Unspecified`
5. **Application username**: Usually `Email`
6. Click **Save**

## Step 7: Update Your settings.json

After getting all three values, your `settings.json` should look like this:

```json
{
  "sp": {
    "entityId": "http://127.0.0.1:5000/api/auth/sso/metadata",
    "assertionConsumerService": {
      "url": "http://127.0.0.1:5000/api/auth/sso/acs",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    }
  },
  "idp": {
    "entityId": "http://www.okta.com/exk1lkg6mwaAZpE3P358",
    "singleSignOnService": {
      "url": "https://your-company.okta.com/app/your-app/exk1lkg6mwaAZpE3P358/sso/saml",
      "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
    },
    "x509cert": "MIIDmDCCAoCgAwIBAgIGAZfCBneWMA0GCSqGSIb3DQEBCwUAMIGMMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEUMBIGA1UECwwLU1NPUHJvdmlkZXIxDTALBgNVBAMMBGdldHMxHDAaBgkqhkiG9w0BCQEWDWluZm9Ab2t0YS5jb20wHhcNMjUwNjMwMTgwNzEzWhcNMzUwNjMwMTgwODEyWjCBjDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoMBE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMQ0wCwYDVQQDDARnZXRzMRwwGgYJKoZIhvcNAQkBFg1pbmZvQG9rdGEuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkIBjRzquU8HgTagxUKSHCR1HRHD79YoWnosHulbX6s6/VQgSYMBijkF/5ym8AvS90ovaSE27iAYbJIdBUsbO4o2VU4htCR4mcPvWAx+PvTVUCGT7ykOJqaGWOreQvF63oZpQA6Po8INuEwc86RPk6gPlBrKRzpRzgglLLKoMnaLD7XO+UaBxze6eMX0MEBSQwkQhuoYaXD/VqEnq9C/qVyTkhLAtUyhdG0WRsqhW1LW0U8ZmFKOmb7P1ljkWHXb4HlMtPGkq5l4UFny6AymlKlzimtc3IVAf/3Is9vzfz3BwT+61qkcXaufkN0RqrblH7kOtyneInfk6k3GJlrJ+RQIDAQAB"
  },
  "security": {
    "authnRequestsSigned": false,
    "wantAssertionsSigned": true,
    "wantMessageSigned": false
  }
}
```

## Quick Reference: Where to Find Each Value

| Value | Location in Okta |
|-------|------------------|
| **Identity Provider Issuer** | Applications → [Your App] → Sign On tab → SAML 2.0 section → Identity Provider Issuer |
| **Single Sign-On URL** | Applications → [Your App] → Sign On tab → SAML 2.0 section → Single Sign-On URL |
| **X.509 Certificate** | Applications → [Your App] → Sign On tab → SAML Signing Certificates → View Certificate |

## Troubleshooting

- **Certificate format error**: Make sure you removed the `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----` lines and all line breaks
- **URL mismatch**: Ensure the URLs in Okta match exactly what's in your `settings.json` (including http vs https)
- **Entity ID mismatch**: The `sp.entityId` in your settings.json must match the "Audience URI" in Okta
- **ACS URL mismatch**: The `sp.assertionConsumerService.url` must match the "Single Sign-On URL" in Okta

## Testing

After configuration, test your setup:

1. Start your Flask application
2. Navigate to: `http://127.0.0.1:5000/api/auth/test/saml-settings` to verify settings are loaded
3. Navigate to: `http://127.0.0.1:5000/api/auth/sso/login` to initiate SSO login

