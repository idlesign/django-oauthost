from pytest_djangoapp import configure_djangoapp_plugin


pytest_plugins = configure_djangoapp_plugin(
    {
        'ROOT_URLCONF': 'oauthost.urls',
    },
    extend_INSTALLED_APPS=[
        'django.contrib.sessions',
    ],
    extend_MIDDLEWARE=[
        'django.middleware.common.CommonMiddleware',
        'django.contrib.sessions.middleware.SessionMiddleware',
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    ],
)
