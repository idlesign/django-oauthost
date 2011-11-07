from functools import wraps

from django.utils.decorators import available_attrs

from utils import check_token, forbidden_error_response


def oauth_required(view_function):
    """Views decorator checking user oauth token."""
    # TODO scope check.
    @wraps(view_function, assigned=available_attrs(view_function))
    def view_wrapped(request, *args, **kwargs):
        if not check_token(request):
            # For now we just use generic error page no matter what
            # token type is used and what that's type spec tells us to do.
            # We are evil enough, I confirm.
            # Yet, it may change some day.
            return forbidden_error_response(request)
        return view_function(request, *args, **kwargs)
    return view_wrapped
