#! /usr/bin/env python
import sys
import os

from django.conf import settings, global_settings


def main():
    current_dir = os.path.dirname(__file__)
    app_name = os.path.basename(current_dir)
    sys.path.insert(0, os.path.join(current_dir, '..'))

    if not settings.configured:
        settings.configure(
            INSTALLED_APPS=('django.contrib.auth', 'django.contrib.contenttypes', 'django.contrib.sessions', app_name),
            DATABASES={'default': {'ENGINE': 'django.db.backends.sqlite3'}},
            ROOT_URLCONF='oauthost.urls',
            MIDDLEWARE_CLASSES=(
                'django.middleware.common.CommonMiddleware',
                'django.contrib.sessions.middleware.SessionMiddleware',
                'django.contrib.auth.middleware.AuthenticationMiddleware',
            ),
            TEMPLATE_CONTEXT_PROCESSORS=tuple(global_settings.TEMPLATE_CONTEXT_PROCESSORS) + (
                'django.core.context_processors.request',
            )
        )

    try:  # Django 1.7 +
        from django import setup
        setup()
    except ImportError:
        pass

    from django.test.utils import get_runner
    runner = get_runner(settings)()
    failures = runner.run_tests((app_name,))

    sys.exit(failures)


if __name__ == '__main__':
    main()
