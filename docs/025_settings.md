# Settings

Oauthost behavior can be customized with the following Django settings.

## OAUTHOST_CODE_LIFETIME

Authorization code time to live in seconds.

Default: `600` (10 minutes, per RFC 6749 recommendation).

Expired codes are rejected with `invalid_grant` error and deleted.

## OAUTHOST_TEMPLATE_AUTHORIZE

Template used to render the authorization (scopes confirmation) page.

Default: `oauthost/authorize.html`

## OAUTHOST_TEMPLATE_AUTHORIZE_ERROR

Template used to render the authorization error page.

Default: `oauthost/authorize_error.html`

## OAUTHOST_TEMPLATE_AUTHORIZE_PROCEED

Template used to render the continue page for clients not supporting
fragment component (`#`) in the HTTP `Location` response header field.

Default: `oauthost/authorize_proceed.html`

## OAUTHOST_TEMPLATE_FORBIDDEN

Template used to render the forbidden (403) page.

Default: `oauthost/forbidden.html`

## OAUTHOST_TEMPLATE_RESTRICTED

Template used to render the restricted area page.

Default: `oauthost/restricted.html`
