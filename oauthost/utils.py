import logging

from django.http import HttpRequest

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
