from functools import wraps

from django.utils.decorators import available_attrs

from oauthost.utils import auth_handler_response


def oauth_required(scope=None, scope_auto=False):
    """Views decorator checking user oauth token.

    ``scope`` - scope identifier string to check token has access to the scope.
    ``scope_auto`` - if *True* scope identifier will be built automatically
        using the following format: '<application_name>:<decorated_view_name>'.
        E.g.: for application named *polls* and having *detail* view scope
        would be *polls:detail*.

    """
    def decorated_view(view_function):
        @wraps(view_function, assigned=available_attrs(view_function))
        def wrapper(request, *args, **kwargs):
            target_scope = scope

            if scope_auto:
                target_scope = '%(app_name)s:%(view_name)s' % {
                    'app_name': view_function.__module__.split('.')[0],
                    'view_name': view_function.__name__}

            return auth_handler_response(request, scope=target_scope) or view_function(request, *args, **kwargs)
        return wrapper

    return decorated_view
