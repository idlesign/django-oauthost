class OauthostException(Exception):
    """Base oauthost exceptions. All the others should inherit from it."""


class EndpointError(OauthostException):
    """Base exception for conflicts occured at endpoints: TokenEndpoint, AuthorizeEndpoint."""

    def as_response(self):
        raise NotImplementedError()
