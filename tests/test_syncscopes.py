import pytest

from django.core.management import call_command
from django.core.management.base import CommandError

from oauthost.models import Scope


VIEWS_SRC = '''
from oauthost.decorators import oauth_required

@oauth_required()
def secured_view(request):
    pass

def plain_view(request):
    pass
'''


@pytest.fixture
def fake_app(tmp_path, settings, monkeypatch):
    """Creates a fake application package and returns its name."""

    def fake_app_(name, views_src=None):
        app_dir = tmp_path / name
        app_dir.mkdir()
        (app_dir / '__init__.py').write_text('')

        if views_src is not None:
            (app_dir / 'views.py').write_text(views_src)

        monkeypatch.syspath_prepend(str(tmp_path))
        settings.INSTALLED_APPS = [*settings.INSTALLED_APPS, name]

        return name

    return fake_app_


class TestSyncScopes:

    def test_no_args(self):
        with pytest.raises(CommandError, match='required'):
            call_command('syncscopes')

    def test_unknown_app(self):
        with pytest.raises(CommandError, match='not in INSTALLED_APPS'):
            call_command('syncscopes', 'unknownapp')

    def test_no_views_module(self, fake_app):
        fake_app('appnoviews')

        with pytest.raises(CommandError, match='No views.py'):
            call_command('syncscopes', 'appnoviews')

    def test_sync(self, fake_app, capsys):
        fake_app('fakeapp', views_src=VIEWS_SRC)

        call_command('syncscopes', 'fakeapp')

        scope = Scope.objects.get(identifier='fakeapp:secured_view')
        assert scope.title == 'Fakeapp Secured View'
        assert not Scope.objects.filter(identifier='fakeapp:plain_view').exists()

        # Existing scopes are kept on a repeated run.
        call_command('syncscopes', 'fakeapp')

        assert Scope.objects.filter(identifier='fakeapp:secured_view').count() == 1
        assert 'already exists' in capsys.readouterr().out
