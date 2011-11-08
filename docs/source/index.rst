django-oauthost documentation
=============================

*django-oauthost is a reusable application for Django, introducing OAuth2 server functionality.*


Requirements
------------

1. Django 1.3+
2. Auth Django contrib package
3. South 0.7.1+ for Django (required for version upgrades)

* Django Admin site contrib package is supported but not a must.


Check list
----------

* MIDDLEWARE_CLASSES has

  `django.contrib.sessions.middleware.SessionMiddleware`

  `django.middleware.csrf.CsrfViewMiddleware`

* TEMPLATE_CONTEXT_PROCESSORS has

  `django.core.context_processors.request`


Precautions
-----------

* Do not use Django's brand new cookie-based session engine, it may cause security issues.
* Do not use OAuth1 clients as they probably won't work.


Things to read
--------------

* OAuth 2.0 Authorization Protocol - http://tools.ietf.org/html/draft-ietf-oauth-v2

All different flavors:

* Yandex - http://api.yandex.ru/oauth/doc/dg/concepts/About.xml
* GitHub - http://developer.github.com/v3/oauth/
* Google - http://code.google.com/intl/en/apis/accounts/docs/OAuth2.html
* Facebook - http://developers.facebook.com/docs/authentication/


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


A hint
------

If the application is not what you want for site navigation, you might be interested in considering
other choices at http://djangopackages.com/grids/g/oauth-servers/