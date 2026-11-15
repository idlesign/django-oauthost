import json
import logging

from django.http import HttpRequest, HttpResponse

LOGGER = logging.getLogger('django.oauthost')  # Exposed to modules.


def get_remote_ip(request: HttpRequest) -> str:
    """Resolves and returns client IP.

    :param request:

    """
    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = request.META.get('REMOTE_ADDR')

    if forwarded is not None:
        ip = forwarded.split(',')[-1].strip()

    return ip or ''


def build_json_response(data_dict: dict, http_status: int = 200, additional_headers: dict = None) -> HttpResponse:
    """Builds a JSON response with no-store cache headers.

    :param data_dict: Document to serialize into JSON.
    :param http_status: Response HTTP status code.
    :param additional_headers: Additional headers to set on the response.

    """
    response = HttpResponse(
        content_type='application/json;charset=UTF-8',
        content=json.dumps(data_dict), status=http_status
    )
    response['Cache-Control'] = 'no-store'
    response['Pragma'] = 'no-cache'

    if additional_headers is None:
        additional_headers = {}

    for key, value in additional_headers.items():
        response[key] = value

    return response
