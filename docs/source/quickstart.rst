Quick start
===========

.. warning::

    OAuth 2 requires secure connections, so oauthost will check for https
    *if your project is not in debug mode*, and will refuse to function
    if check fails.


Preparations
------------

0. Initialize DB tables for oauthost, run from command line:

   ``python manage.py migrate``


1. Attach `oauthost.urls` to project `urls`.

    Authorization endpoint would be available at `{ BASE_URL }auth/`.

    Token endpoint would be available at `{ BASE_URL }token/`.

2. Decorate application views which require OAuth 2 authorization with `oauth_required`::

    @oauth_required(scope='my_articles_app:my_summary')
    def summary(request, article_id):
        """Scope associated with this view is `my_articles_app:my_summary`."""
        ...

    @oauth_required(scope_auto=True)
    def results(request, poll_id):
        """Scope for this view would be evaluated to `polls:results` if this view is in `polls` app."""
        ...

3. Use Django's Admin site contrib package to manipulate oauthost data (e.g. register clients).

    3.1. Register *scopes* for your Django application.

    Scope identifiers might be, e.g.: `polls:index`, `polls:detail`, `polls:results`.

    .. note::

        You can also use ``syncscopes`` management command which automatically creates
        scopes for `oauth_required` decorated views available in application(s) which
        names are passed to the command::

            python manage.py syncscopes polls

    3.2. Register *client* which could be granted with access to your resources.

    .. note::

        Just right there on client registration page you can set up redirection endpoints,
        register authorization codes and issue tokens. Latter two should normally be
        issued to client itself as described in paragraph no 4.


Tokens and protected resources
------------------------------

4. Access authorization and/or token endpoints (see no 1 above) from within
the client (registered in no 3.2) to gain credentials (namely an *access token*)
to access protected views.

    4.1. First your client needs to get an access token and there are several ways to get it.

        .. note::

            In the examples below we use client with ID 1234, which has one redirection
            endpoint (e.g. `http://myapp.com/`).

        4.1.1. Grant token through authorization code.

            1. Request for authorization code with GET HTTP method::

                {BASE_URL}auth/?client_id=1234&response_type=code

            2. Grab `code` param value from URL your client is redirected to (e.g. `http://myapp.com/`).
            3. Exchange authorization code for access token using POST HTTP method::

                {BASE_URL}token/ grant_type=authorization_code&code={code_from_no_2}&redirect_uri=http://myapp.com/&client_id=1234

            4. Get `access_token` param value from JSON document returned by server.

        4.1.2. Grant token implicitly.

            1. Request for authorization code with GET HTTP method::

                {BASE_URL}auth/?client_id=1234&response_type=token

            2. Get `access_token` param value from JSON document returned by server.

    4.2. Second your client should supply token from no 4.1 (or no 3.2) to server when
    accessing any protected views of your application.
    Currently there are three ways to do it. Let's suppose our access token is 987654.

        4.2.1. Recommended way is to pass token in HTTP Authorization Bearer header::

            GET /polls HTTP/1.1
            Host: myapp.com
            Authorization: Bearer 987654

        4.2.2. You can also use POST HTTP method (`access_token` param is checked)::

            POST /polls HTTP/1.1
            Host: myapp.com
            Content-Type: application/x-www-form-urlencoded

            access_token=987654

        4.2.3. Finally you can use GET HTTP method (`access_token` param is checked)::

            GET /polls?access_token=987654 HTTP/1.1
            Host: myapp.com