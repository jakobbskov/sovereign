"""UI localization against isolated fixture databases; never production data."""
import json
import re
import subprocess
import sys
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import pytest
from markupsafe import escape

import app as auth
import db


class Links(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.items = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.items.append(dict(attrs))


def link_to(html, path):
    return next(link["href"] for link in Links(html).items
                if urlsplit(link["href"]).path == path)


def return_to(html):
    return json.loads(re.search(r"const returnTo = (.*);", html).group(1))


@pytest.mark.parametrize("query,expected", [
    ({}, "da"), ({"lang": "da"}, "da"), ({"lang": "en"}, "en"),
    ({"lang": "fr"}, "da"), ({"lang": ""}, "da"),
    ({"lang": "EN"}, "da"), ({"lang": " en "}, "da"),
    ({"lang": "en\x00"}, "da"), ({"lang": "<script>"}, "da"),
    ({"lang": ["en", "da"]}, "da"), ({"lang": ["en", "en"]}, "da"),
    ({"return_to": "https://apps.innosocia.dk/?lang=en"}, "en"),
    ({"return_to": "https://apps.innosocia.dk/?lang=fr"}, "da"),
    ({"return_to": "https://apps.innosocia.dk/?lang=en&lang=da"}, "da"),
    ({"return_to": "https://apps.innosocia.dk/?lang=%00en"}, "da"),
    ({"return_to": "https://apps.innosocia.dk.evil.invalid/?lang=en"}, "da"),
    ({"lang": "", "return_to": "https://apps.innosocia.dk/?lang=en"}, "da"),
    ({"lang": "fr", "return_to": "https://apps.innosocia.dk/?lang=en"}, "da"),
    ({"lang": "da", "return_to": "https://apps.innosocia.dk/?lang=en"}, "da"),
])
def test_language_selection(client, query, expected):
    response = client.get('/login', query_string=query, headers={"Accept-Language": "en"})
    assert response.status_code == 200
    assert f'<html lang="{expected}">' in response.text
    assert not response.headers.getlist('Set-Cookie')


@pytest.mark.parametrize("lang", ["da", "en"])
@pytest.mark.parametrize("page", ["/", "/login", "/register", "/account", "/admin/users"])
def test_localized_pages_render(client, login, monkeypatch, page, lang):
    login()
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    response = client.get(page, query_string={"lang": lang})
    assert response.status_code == 200
    assert f'<html lang="{lang}">' in response.text
    expected = {
        '/': ('Auth-service kører.', 'Auth service is running.'),
        '/login': ('Brugernavn', 'Username'),
        '/register': ('Gentag password', 'Confirm password'),
        '/account': ('Konto-oplysninger', 'Account details'),
        '/admin/users': ('Alle roller', 'All roles'),
    }[page][lang == 'en']
    assert expected in response.text
    assert '{{' not in response.text
    assert '{t(' not in response.text


@pytest.mark.parametrize('lang', ['da', 'en'])
@pytest.mark.parametrize("origin", ["https://apps.innosocia.dk", "https://writer.innosocia.dk"])
def test_login_register_links_round_trip(client, monkeypatch, lang, origin):
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    target = origin + '/path?one=a+b&lang=en&next=%2Ffoo#part&lang=fr'
    response = client.get('/login', query_string={'return_to': target, 'lang': lang})
    for path in ('/register', '/account'):
        query = parse_qs(urlsplit(link_to(response.text, path)).query)
        assert query == {'return_to': [target], 'lang': [lang]}
    registration = client.get(link_to(response.text, '/register'))
    back = client.get(link_to(registration.text, '/login'))
    assert f'<html lang="{lang}">' in registration.text
    assert return_to(registration.text) == return_to(back.text) == target


def test_build_auth_query_encodes_all_parameter_boundaries():
    target = 'https://apps.innosocia.dk/a?x=1&lang=fr&q=+%20#fragment'
    encoded = auth.build_auth_query(target, 'en')
    assert parse_qs(encoded) == {'return_to': [target], 'lang': ['en']}
    assert encoded.count('&') == 1
    assert '#' not in encoded
    assert parse_qs(auth.build_auth_query(target, 'en&return_to=https://evil.invalid'))['lang'] == ['da']


@pytest.mark.parametrize('target', [
    'https://apps.innosocia.dk.evil.invalid/?lang=en',
    'https://apps.innosocia.dk@evil.invalid/?lang=en',
    'https://evil.apps.innosocia.dk/?lang=en',
    'https://apps.innosocia.dk:444/?lang=en',
    'https://apps.innosocia.dk\\@evil.invalid/?lang=en',
    'https://apps.innosocia.dk\n.evil.invalid/?lang=en',
    '//evil.invalid/?lang=en', 'javascript:alert(1)', 'https://[broken/',
])
def test_auth_query_retains_exact_origin_validation(client, target):
    encoded = auth.build_auth_query(target, 'en')
    assert parse_qs(encoded)['return_to'] == ['https://strength.innosocia.dk']
    assert return_to(client.get('/login', query_string={'return_to': target}).text) == 'https://strength.innosocia.dk'


@pytest.mark.parametrize('lang', ['da', 'en'])
@pytest.mark.parametrize('page', ['/login', '/register', '/account'])
def test_localized_html_and_js_escape_hostile_values(client, login, users, monkeypatch, lang, page):
    login()
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    hostile = '\"><script>window.localizationProbe=1</script><img src=x onerror="alert(1)">'
    target = 'https://apps.innosocia.dk/?q=' + hostile
    db.update_user_profile(users['admin'], hostile, hostile, auth.now_utc_iso())
    response = client.get(page, query_string={'lang': lang, 'return_to': target})
    assert hostile not in response.text
    assert '<script>window.localizationProbe=1</script>' not in response.text
    assert return_to(response.text) == target
    encoded = re.search(r'const returnTo = (.*);', response.text).group(1)
    assert '<' not in encoded and '\\u003c' in encoded
    if page == '/account':
        assert str(escape(hostile)) in response.text
        assert next(a['href'] for a in Links(response.text).items if a.get('id') == 'backLink') == target


@pytest.mark.parametrize('page', ['/login', '/register', '/account', '/admin/users'])
def test_translation_strings_are_context_escaped(client, login, monkeypatch, page):
    login()
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    hostile = "</script><script>alert('translation')</script>` ${evil} & \""
    monkeypatch.setattr(auth, 'tr_auth', lambda lang, key: hostile)
    response = client.get(page, query_string={'lang': 'en'})
    assert hostile not in response.text
    assert str(escape(hostile)) in response.text
    scripts = re.findall(r'<script>(.*?)</script>', response.text, re.S)
    assert len(scripts) == 1
    checked = subprocess.run(['node', '--check'], input=scripts[0], text=True, capture_output=True)
    assert checked.returncode == 0, checked.stderr


@pytest.mark.parametrize('page', ['/account', '/admin/users'])
def test_unauthenticated_return_preserves_language_without_trusting_host(client, page):
    target = 'https://apps.innosocia.dk/?lang=en&filter=one#two'
    response = client.get(page, query_string={'lang': 'en', 'return_to': target},
                          base_url='https://untrusted.invalid')
    login_link = link_to(response.text, '/login')
    query = parse_qs(urlsplit(login_link).query)
    assert query['lang'] == ['en']
    destination = urlsplit(query['return_to'][0])
    assert destination.netloc == 'auth.innosocia.dk'
    assert destination.path == page
    assert parse_qs(destination.query)['lang'] == ['en']
    if page == '/account':
        assert parse_qs(destination.query)['return_to'] == [target]


def test_disabled_registration_and_denied_admin_preserve_language(client, login, monkeypatch):
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', False)
    target = 'https://apps.innosocia.dk/?lang=en'
    disabled = client.get('/register', query_string={'lang': 'en', 'return_to': target})
    assert 'Registration is disabled.' in disabled.text
    assert parse_qs(urlsplit(link_to(disabled.text, '/login')).query) == {'return_to': [target], 'lang': ['en']}
    login('user')
    denied = client.get('/admin/users?lang=en')
    assert 'Access denied.' in denied.text
    assert link_to(denied.text, '/account') == '/account?lang=en'


@pytest.mark.parametrize('lang', ['da', 'en', 'bad'])
def test_authentication_and_entitlements_contract_unchanged(client, login, users, lang):
    anonymous = client.get('/api/auth/validate', query_string={'lang': lang})
    assert anonymous.status_code == 401
    assert anonymous.json == {'ok': False, 'authenticated': False}
    invalid = client.post('/api/auth/login', query_string={'lang': lang},
                          json={'username': 'admin', 'password': 'wrong-password'})
    assert invalid.status_code == 401
    assert invalid.json == {'ok': False, 'error': 'invalid credentials'}
    token = login()
    query = {'lang': lang}
    before = client.get('/api/auth/validate', query_string=query)
    assert before.json == {'ok': True, 'authenticated': True, 'user_id': users['admin'],
                           'username': 'admin', 'role': 'admin', 'entitlements': []}
    url = f'/api/admin/users/{users["admin"]}/entitlements'
    payload = {'app_key': 'writer', 'granted': True}
    blocked = client.post(url, query_string=query, json=payload)
    assert blocked.status_code == 403
    assert blocked.json == {'ok': False, 'error': 'invalid csrf token'}
    granted = client.post(url, query_string=query, json=payload, headers={'X-CSRF-Token': token})
    assert granted.json == {'ok': True, 'user_id': users['admin'], 'entitlements': ['writer']}
    validated = client.get('/api/auth/validate', query_string=query)
    assert validated.json == dict(before.json, entitlements=['writer'])
    assert validated.headers['Cache-Control'] == 'no-store'
    assert 'Access-Control-Allow-Origin' not in client.get('/api/admin/csrf?lang=en', headers={'Origin': 'https://apps.innosocia.dk'}).headers
    revoked = client.post(url, query_string=query, json={'app_key': 'writer', 'granted': False},
                          headers={'X-CSRF-Token': token})
    assert revoked.json['entitlements'] == []


@pytest.mark.parametrize('lang', ['da', 'en'])
def test_registration_contract_is_not_translated(client, monkeypatch, lang):
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    response = client.post('/api/auth/register', query_string={'lang': lang}, json={
        'username': 'localization-user', 'password': 'test-password-long',
        'confirm_password': 'test-password-long', 'email': 'localization@example.invalid',
    })
    assert response.status_code == 200
    assert response.json['ok'] is True
    assert response.json['user']['role'] == 'user'
    assert client.get('/api/auth/validate?lang=' + lang).json['entitlements'] == []


@pytest.mark.parametrize('lang', ['da', 'en'])
def test_embedded_javascript_syntax(client, login, monkeypatch, lang):
    login()
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    for page in ('/login', '/register', '/account', '/admin/users'):
        html = client.get(page, query_string={'lang': lang}).text
        scripts = re.findall(r'<script>(.*?)</script>', html, re.S)
        assert len(scripts) == 1
        checked = subprocess.run(['node', '--check'], input=scripts[0], text=True, capture_output=True)
        assert checked.returncode == 0, (page, checked.stderr)


def test_gunicorn_import_and_wsgi_health_without_database(tmp_path):
    # In a fresh process block EVERY database connection before importing the WSGI app.
    code = '''
import sqlite3
from gunicorn.util import import_app
from werkzeug.test import Client
from werkzeug.wrappers import Response
def reject(*args, **kwargs):
    raise AssertionError("WSGI import/health must not access a database")
sqlite3.connect = reject
application = import_app("app:app")
response = Client(application, Response).get("/api/health")
assert response.status_code == 200
assert response.json == {"ok": True, "service": "sovereign-core-auth"}
'''
    result = subprocess.run([sys.executable, '-B', '-c', code], cwd=db.BASE_DIR,
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def run_ui(html, behavior):
    script = re.search(r'<script>(.*?)</script>', html, re.S).group(1)
    # Execute real rendered JS with a small DOM/fetch double, not production requests.
    harness = r'''
const assert = require('node:assert/strict');
const elements = new Map();
function element(){
  return {value:'test-password-long', textContent:'', innerHTML:'', className:'',
    children:[], handlers:{}, classList:{add(){}, remove(){}}, style:{},
    addEventListener(name, fn){ this.handlers[name] = fn; },
    querySelectorAll(){ return []; }, setAttribute(){}, removeAttribute(){},
    replaceChildren(){ this.children = []; }, append(child){ this.children.push(child); },
    reset(){}};
}
const document = {
  getElementById(id){ if (!elements.has(id)) elements.set(id, element()); return elements.get(id); },
  createElement(){ return element(); }
};
const location = {href:'', reload(){}};
const window = {location};
const calls = [];
let responseFor = () => ({});
async function fetch(url, options={}){
  calls.push({url, options});
  return {ok:true, status:200, json:async () => responseFor(url, options)};
}
(async () => {
'''
    result = subprocess.run(['node'], input=harness + script + '\n' + behavior +
                            '\n})().catch(error => { console.error(error); process.exitCode=1; });',
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize('lang', ['da', 'en'])
@pytest.mark.parametrize("origin", ["https://apps.innosocia.dk", "https://writer.innosocia.dk"])
def test_login_password_reset_and_logout_javascript_flow(client, login, users, lang, origin):
    target = origin + '/?lang=en&view=home#launch'
    html = client.get('/login', query_string={'lang': lang, 'return_to': target}).text
    run_ui(html, '''
await new Promise(resolve => setImmediate(resolve));
responseFor = () => ({user:{must_change_password:true}});
await elements.get('loginForm').handlers.submit({preventDefault(){}});
const next = new URL(location.href, 'https://auth.innosocia.dk');
assert.equal(next.pathname, '/account');
assert.equal(next.searchParams.get('lang'), ''' + json.dumps(lang) + ''');
assert.equal(next.searchParams.get('return_to'), ''' + json.dumps(target) + ''');
responseFor = () => ({user:{must_change_password:false}});
await elements.get('loginForm').handlers.submit({preventDefault(){}});
assert.equal(location.href, ''' + json.dumps(target) + ''');
responseFor = () => ({authenticated:true});
location.href = '';
assert.equal(await goIfAlreadyLoggedIn(), true);
assert.equal(location.href, ''' + json.dumps(target) + ''');
''')
    login()
    db.set_user_must_change_password(users['admin'], 1, auth.now_utc_iso())
    account = client.get('/account', query_string={'lang': lang, 'return_to': target}).text
    assert ('midlertidigt nulstillet' if lang == 'da' else 'temporarily reset') in account
    run_ui(account, '''
assert.equal(elements.get('currentPasswordField').style.display, 'none');
await elements.get('passwordForm').handlers.submit({preventDefault(){}});
assert.equal(calls.at(-1).url, '/api/auth/complete-password-reset');
await elements.get('logoutBtn').handlers.click();
assert.equal(calls.at(-1).url, '/api/auth/logout');
const next = new URL(location.href, 'https://auth.innosocia.dk');
assert.equal(next.pathname, '/login');
assert.equal(next.searchParams.get('lang'), ''' + json.dumps(lang) + ''');
assert.equal(next.searchParams.get('return_to'), ''' + json.dumps(target) + ''');
''')


@pytest.mark.parametrize('lang', ['da', 'en'])
@pytest.mark.parametrize("origin", ["https://apps.innosocia.dk", "https://writer.innosocia.dk"])
def test_registration_javascript_returns_to_launcher(client, monkeypatch, lang, origin):
    monkeypatch.setattr(auth, 'ALLOW_REGISTRATION', True)
    target = origin + '/?lang=en&app=writer#start'
    html = client.get('/register', query_string={'lang': lang, 'return_to': target}).text
    run_ui(html, '''
await elements.get('registerForm').handlers.submit({preventDefault(){}});
assert.equal(calls.at(-1).url, '/api/auth/register');
assert.equal(location.href, ''' + json.dumps(target) + ''');
assert.equal(elements.get('status').textContent, ''' + json.dumps(auth.tr_auth(lang, 'status_register_ok')) + ''');
''')


@pytest.mark.parametrize('lang', ['da', 'en'])
def test_admin_javascript_localization_preserves_csrf_and_machine_values(client, login, lang):
    login()
    html = client.get('/admin/users', query_string={'lang': lang}).text
    run_ui(html, '''
await new Promise(resolve => setImmediate(resolve));
renderUsers([{id:2, username:'<img onerror=alert(1)>', email:'a&b', role:'user', is_active:0}]);
assert.ok(elements.get('usersBody').innerHTML.includes('&lt;img'));
assert.ok(!elements.get('usersBody').innerHTML.includes('<img'));
assert.ok(elements.get('usersBody').innerHTML.includes('data-role="admin"'));
assert.ok(elements.get('usersBody').innerHTML.includes('data-label="' + ''' + json.dumps(auth.tr_auth(lang, 'username')) + ''' + ': '));
elements.get('statusFilter').value = 'inactive';
const container = element();
const row = {getAttribute(){return '2';}, querySelector(){return container;}};
let granted = false;
responseFor = (url, options) => {
  if (url === '/api/admin/csrf') return {csrf_token:'fixture-csrf'};
  if (url === '/api/admin/apps') return {items:[{key:'writer', name:'<b>Catalog name</b>'}]};
  if (options.method === 'POST') {
    assert.equal(options.headers['X-CSRF-Token'], 'fixture-csrf');
    assert.deepEqual(JSON.parse(options.body), {app_key:'writer', granted:!granted});
    granted = !granted;
  }
  return {entitlements:granted ? ['writer'] : []};
};
await showEntitlements(row);
assert.ok(container.children[0].textContent.startsWith('<b>Catalog name</b> (writer):'));
assert.equal(container.children[0].children[0].textContent, ''' + json.dumps(auth.tr_auth(lang, 'grant')) + ''');
await container.children[0].children[0].handlers.click();
assert.equal(granted, true);
assert.equal(container.children[0].children[0].textContent, ''' + json.dumps(auth.tr_auth(lang, 'revoke')) + ''');
await container.children[0].children[0].handlers.click();
assert.equal(granted, false);
''')


def test_language_does_not_leak_between_requests(client):
    assert '<html lang="en">' in client.get('/login?lang=en').text
    assert '<html lang="da">' in client.get('/login').text
    assert '<html lang="da">' in client.get('/login?lang=%FF').text
