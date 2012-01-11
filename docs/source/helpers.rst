Helpers
=======


Piston Authentication class
---------------------------

Piston is a mini-framework for Django for creating RESTful APIs - http://bitbucket.org/jespern/django-piston/wiki/Home

Oauthost comes with an authentication class for Piston resources.

Piston resource view creation example::

    from piston.resource import Resource
    from oauthost.utils import PistonAuthHelper

    my_resource_view = Resource(MyResourceHandler, authentication=PistonAuthHelper('my_resource:my_scope'))


See Piston documentation for more information on authentication customizations.
