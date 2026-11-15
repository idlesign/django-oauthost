"""OpenAPI (drf-spectacular) support for oauthost DRF integration.

Registers the Bearer security scheme for oauthost tokens in generated
OpenAPI schemas. Optional, requires drf-spectacular.

"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension


class OAuthostAuthenticationScheme(OpenApiAuthenticationExtension):
    """Describes oauthost Bearer authentication in OpenAPI terms."""

    target_class = 'oauthost.integration.drf.OAuthostAuthentication'
    name = 'Bearer'

    def get_security_definition(self, auto_schema) -> dict:
        return {
            'type': 'http',
            'scheme': 'bearer',
        }
