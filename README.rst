django-oauthost
===============
http://github.com/idlesign/django-oauthost

.. image:: https://badge.fury.io/py/django-oauthost.png
    :target: http://badge.fury.io/py/django-oauthost

.. image:: https://pypip.in/d/django-oauthost/badge.png
        :target: https://crate.io/packages/django-oauthost


What's that
-----------

*django-oauthost is a reusable application for Django, introducing OAuth2 server.*

It allows to guard your application views with OAuth 2.0 in quite a trivial way.

1. Register your client using Django Admin or API::

    from oauthost.toolbox import register_client

    ...

    # Define some scopes to restrict our client to.
    my_scopes = ['polls:vote']

    # `user` might be `request.user` if in a view.
    register_client('My OAuth Client', 'my_client', user, scopes_list=my_scopes)

    ...

2. Decorate your views with `oauth_required` (suppose in `polls.views`)::

    from oauthost.decorators import oauth_required

    @oauth_required(scope_auto=True)
    def vote(request, poll_id, variant_id):
        ...


3. Attach `oauthost.urls` to project `urls` (in `urls.py`)::

        from oauthost.urls import urlpatterns as oauthost_urlpatterns

        urlpatterns = ...  # Your actual urlpatterns are ommited.

        urlpatterns += oauthost_urlpatterns

   After that authorization endpoint is available at `{ BASE_URL }auth/`.

   Token endpoint is available at `{ BASE_URL }token/`.


That's all for **oauthost**, connect using your client.

More information is available, read the docs!


Documentation
-------------

http://django-oauthost.readthedocs.org/
