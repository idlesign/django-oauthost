from django import forms
from django.db import models
from django.conf import settings


# This allows South to handle our custom 'URLSchemeField' field.
if 'south' in settings.INSTALLED_APPS:
    from south.modelsinspector import add_introspection_rules

    add_introspection_rules([], ['^oauthost\.fields\.URLSchemeField'])


class URLShemeFormField(forms.URLField):
    def __init__(self, *args, **kwargs):
        super(URLShemeFormField, self).__init__(*args, **kwargs)
        del self.validators[-1]


class URLSchemeField(models.URLField):
    def __init__(self, verbose_name=None, name=None, **kwargs):
        models.URLField.__init__(self, verbose_name, name, **kwargs)
        del self.validators[-1]

    def formfield(self, **kwargs):
        defaults = {'form_class': URLShemeFormField}
        defaults.update(kwargs)
        return super(URLSchemeField, self).formfield(**defaults)
