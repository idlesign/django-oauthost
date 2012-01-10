django-oauthost documentation
=============================

*django-oauthost is a reusable application for Django, introducing OAuth2 server functionality.*

.. warning::

    Alpha stage project - not to be used in production.


Requirements
------------

1. Django 1.3+
2. Auth Django contrib package
3. South 0.7.1+ for Django (required for version upgrades)
4. Django Admin site contrib package (for quick oauthost data manipulation).


Check list
----------

* Do not use Django's brand new cookie-based session engine with oauthost, it may cause security issues.
* Do not use OAuth1 clients as they probably won't work.
* MIDDLEWARE_CLASSES has

  `django.contrib.sessions.middleware.SessionMiddleware`

  `django.middleware.csrf.CsrfViewMiddleware`

* TEMPLATE_CONTEXT_PROCESSORS has

  `django.core.context_processors.request`


Table of Contents
-----------------

.. toctree::
    :maxdepth: 2

    quickstart
    references


Get involved into django-oauthost
---------------------------------

**Submit issues.** If you spotted something weird in application behavior or want to propose a feature you can do
that at https://github.com/idlesign/django-oauthost/issues

**Write code.** If you are eager to participate in application development, fork it
at https://github.com/idlesign/django-oauthost, write your code, whether it should be a bugfix or a feature
implementation, and make a pull request right from the forked project page.

**Translate.** If want to translate the application into your native language use Transifex:
https://www.transifex.net/projects/p/django-oauthost/.

**Spread the word.** If you have some tips and tricks or any other words in mind that you think might be of interest
for the others — publish it.


The tip
-------

If the application is not what you want for site navigation, you might be interested in considering
other choices at http://djangopackages.com/grids/g/oauth-servers/