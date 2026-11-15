# django-oauthost changelog

### Unreleased
* ++ Added Usage scenarios documentation page with diagrams.
* ++ Test coverage raised from 75% to 93%.
* ** Abstract method stubs are now excluded from coverage report.
* ** Admin contrib enabled in tests, admin module is now covered.
* ** Dropped dead compatibility code for South and Django below 2.0.
* ** Extracted common save-with-regeneration logic into OauthostModel base model.
* ** Fixed implicit grant description in quickstart.
* ** Fixed oauth_required decorator broken by available_attrs import removed in modern Django.
* ** Fixed syncscopes command unable to accept arguments on modern Django.
* ** Fixed URLSchemeField rejecting custom URI schemes on modern Django.

### v1.2.0 [2026-11-15]
* !! Authorization codes are now cryptographically random 43-char strings instead of 7-digit numbers (kudos Sanjeev Kumar).
* ++ Authorization codes now expire after OAUTHOST_CODE_LIFETIME seconds, 10 minutes by default (kudos Sanjeev Kumar).
* ** Client secrets are now compared in constant time.
* ** Fixed naive datetime usage in token issuing, renewal and validation.

### v1.1.2 [2026-11-14]
* ** Fixed Model.save() calls to pass force_insert/force_update as keywords (modern Django compatibility).
* ** Pinned default_auto_field to AutoField to prevent id field drift on Django 6.1.

### v1.1.1 [2021-12-18]
* ** Django 4.0 compatibility improved.
* ** Drop support for Python 3.5.

### v1.1.0 [2019-12-07]
* !! Dropped QA for Django 1.7.
* !! Dropped QA for Python 2.
* ++ Add Django 3.0 compatibility.

### v1.0.0
* !! Dropped QA for Python 3.4.
* ** No functional changes. Celebrating 1.0.0.

### v0.5.0
* ++ Django 2.0 basic compatibility.
* ** Dropped support for Python<3.4 and Django<1.7.

### v0.4.0
* ++ Added Django 1.7+ config and migrations.
* ++ Added Russian localization.
* ** Django 1.8, 1.9, 1.10 adaptations
* ** Minor code improvements.

### v0.3.0
* ++ Added Russian loco.
* ++ Added new param `redirect_uri` to `register_client()`.

### v0.2.0
* ++ API refactored.
* ++ Implemented advanced scopes handling.
* ++ Added Scope status.
* ++ toolbox.register_client() is implemented.
* ** Fixed Django 1.6 import error in urls.py.
* ** `authorization_code` grant type now copies token scopes from code.

### v0.1.0
* ++ Added Py3 support.
* ++ Added Django 1.5 custom user model support.
* ** Fixed auth session flushes in endpoint_authorize issues.

### v0.0.3
* ++ Added support for custom URI schemes in redirection endpoints.
* ** Fixed Piston auth.

### v0.0.2
* ++ API refactored.
* ++ New `synscopes` management command.
* ++ Added authentication helper class for Piston.
* ** Bearer token type fixes.

### v0.0.1
* ++ Basic OAuth 2 functionality.
