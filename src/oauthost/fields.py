from django import forms
from django.db import models


class URLShemeFormField(forms.URLField):

    default_validators = []


class URLSchemeField(models.URLField):

    default_validators = []

    def formfield(self, **kwargs):
        defaults = {'form_class': URLShemeFormField}
        defaults.update(kwargs)
        return super().formfield(**defaults)
