import logging


LOGGER = logging.getLogger('django.oauthost')


def get_remote_ip(request):
    """Resolves and returns client IP."""

    forwarded = request.META.get('HTTP_X_FORWARDED_FOR')
    ip = request.META.get('REMOTE_ADDR')
    if forwarded is not None:
        ip = forwarded.split(',')[-1].strip()
    return ip
