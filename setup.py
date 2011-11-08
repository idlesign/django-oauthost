import os
from setuptools import setup
from oauthost import VERSION

f = open(os.path.join(os.path.dirname(__file__), 'README'))
readme = f.read()
f.close()

setup(
    name='django-oauthost',
    version='.'.join(map(str, VERSION)),
    description='This reusable Django application introduces OAuth2 server functionality.',
    long_description=readme,
    author="Igor 'idle sign' Starikov",
    author_email='idlesign@yandex.ru',
    url='http://github.com/idlesign/django-oauthost',
    packages=['oauthost'],
    include_package_data=True,
    install_requires=['setuptools'],
    zip_safe=False,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Framework :: Django',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        ],
)
