import pytest

from drf_spectacular.generators import SchemaGenerator


@pytest.fixture(autouse=True)
def root_urlconf(settings):
    settings.ROOT_URLCONF = 'urls_drf'


class TestOpenApi:

    def test_security_scheme_registered(self):
        generator = SchemaGenerator()
        schema = generator.get_schema(request=None, public=True)

        schemes = schema['components']['securitySchemes']

        assert schemes['Bearer'] == {'type': 'http', 'scheme': 'bearer'}

    def test_operation_requires_bearer(self):
        generator = SchemaGenerator()
        schema = generator.get_schema(request=None, public=True)

        operation = schema['paths']['/plain/']['get']

        assert operation['security'] == [{'Bearer': []}]
