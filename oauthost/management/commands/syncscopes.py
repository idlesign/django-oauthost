from os import path
from inspect import getfile

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db import IntegrityError

from oauthost.models import Scope


class Command(BaseCommand):

    args = '<app_name app_name ...>'
    help = (
        'Registers OAuth2 scopes from application views in form of `<application_name>:<decorated_view_name>`.'
        'It requires views.py to reside in application directory. Use @oauth_required to decorate view '
        'which requires scope syncing.')

    def handle(self, *args, **options):

        if not len(args):
            raise CommandError('This command accepts space delimited list of application names.')

        if not set(args).issubset(settings.INSTALLED_APPS):
            raise CommandError('One or more application names issued to the command are not in INSTALLED_APPS.')

        for app_name in args:

            decorated_views_count = 0

            self.stdout.write('Working on "%s" application ...\n' % app_name)
            try:
                app_views = __import__('%s.views' % app_name)
            except ImportError:
                raise CommandError('No views.py found in the application.')

            app_views_substr = path.join('oauthost', 'decorators.py')

            for func_name in dir(app_views.views):
                if '__' not in func_name:
                    func = getattr(app_views.views, func_name)
                    # That's how we find decorated views.
                    if func_name != 'oauth_required' and app_views_substr in getfile(func):
                        decorated_views_count += 1
                        # TODO That would be nice to have here a value of `scope` parameter of @oauth_required if it set.
                        # That is, of course, if only we can trace it up at a low cost.
                        scope_name = '%(app_name)s:%(view_name)s' % {'app_name': app_name, 'view_name': func_name}
                        self.stdout.write('    Found "%s" view. Syncing "%s" scope ... ' % (func_name, scope_name))
                        # A try to give our scope a pretty name.
                        scope_title = '%s %s' % (app_name.capitalize(), ' '.join([word.capitalize() for word in func_name.split('_')]))
                        scope = Scope(identifier=scope_name, title=scope_title)
                        try:
                            scope.save()
                        except IntegrityError:
                            self.stdout.write('WARNING: Scope skipped as already exists\n')
                        else:
                            self.stdout.write('Done\n')

            if not decorated_views_count:
                self.stdout.write('NOTE: No views decorated with "@oauth_required" are found in the application.\n')

            self.stdout.write('\n')
