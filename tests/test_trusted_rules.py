"""Live Semgrep checks for the service-owned rules. Every snippet is its own file in one scan; nothing is executed."""
import difflib
from pathlib import Path

import pytest
import yaml

from analyzers.semgrep_runner import run_semgrep
from analyzers.triage import added_lines, gate, triage
from trusted_rules import OFFLINE_RULESET

RULES = yaml.safe_load(OFFLINE_RULESET)['rules']
PYTHON_RULES = {rule['id'] for rule in RULES if rule['languages'] == ['python']}
JAVASCRIPT_RULES = {rule['id'] for rule in RULES if rule['languages'] == ['javascript', 'typescript']}

# Request-data rules need a route around the snippet.
FLASK_APP = 'from flask import Flask, request\napp = Flask(__name__)\n'
EXPRESS_APP = "const express = require('express');\nconst app = express();\n"

# rule: (snippets it must report, snippets that must produce no finding at all)
PYTHON_CASES = {
    'py-weak-md5': ([
        'import hashlib\nhashlib.md5(data)',
        'import hashlib\nhashlib.md5(data)  # nosemgrep',
        'import hashlib\nh = hashlib.md5()\nh.update(blob)',
    ], [
        'import hashlib\nhashlib.sha256(data)',
        'import hashlib\nhashlib.md5(url.encode(), usedforsecurity=False).hexdigest()',
    ]),
    'py-weak-sha1': ([
        'import hashlib\nhashlib.sha1(data).hexdigest()',
    ], [
        'import hashlib\nhashlib.sha512(data)',
        'import hashlib\nhashlib.sha1(etag_source, usedforsecurity=False)',
    ]),
    'py-unsafe-yaml-load': (['yaml.load(text)', 'yaml.load(text, Loader=yaml.Loader)'],
                            ['yaml.load(text, Loader=yaml.SafeLoader)', 'yaml.safe_load(text)']),
    'py-unsafe-yaml-unsafe-load': (['yaml.unsafe_load(text)'], ['yaml.safe_dump(data)']),
    'py-insecure-deserialization-pickle-loads': (['pickle.loads(blob)'], ['pickle.dumps(obj)']),
    'py-insecure-deserialization-pickle-load': (['pickle.load(stream)'], ['json.load(stream)']),
    'py-os-system': (['os.system(cmd)'], ['os.getcwd()']),
    'py-os-popen': (['os.popen(cmd)', 'os.popen3(cmd)'], ['os.path.join(a, b)']),
    'py-subprocess-shell-true': (['subprocess.run(cmd, shell=True)', 'subprocess.check_output(cmd, shell=True)'],
                                 ["subprocess.run(['git', 'log'], check=True)", 'subprocess.run(cmd, shell=False)']),
    'py-dangerous-eval': (['eval(expr)'], ['ast.literal_eval(expr)']),
    'py-dangerous-exec': (['exec(code)'], ['executor.submit(job)']),
    'py-requests-disable-verify': (['requests.get(url, verify=False)', 'requests.post(url, data=d, verify=False)'],
                                   ['requests.get(url, timeout=5)', 'requests.get(url, verify=True)']),
    'py-random-for-secrets': (['random.randint(100000, 999999)'], ['secrets.token_hex(16)']),
    'py-tempfile-mktemp': (['tempfile.mktemp()'], ['tempfile.mkstemp()']),
    'py-tarfile-extractall': (['tarfile.open(path).extractall(dest)',
                               'with tarfile.open(path) as archive:\n    archive.extractall(dest)'],
                              ['tarfile.open(path).getnames()']),
    'py-sql-injection': ([
        # Also a formatted query: the runner keeps only the more severe finding for the line.
        FLASK_APP + "def find(cur):\n    name = request.args['name']\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
        FLASK_APP + 'def find(cur):\n    cur.execute("SELECT * FROM users WHERE id = " + request.args[\'id\'])',
        FLASK_APP + 'def find(cur):\n    q = "SELECT * FROM users WHERE name = \'%s\'" % request.form.get(\'name\')\n    cur.execute(q)',
        FLASK_APP + 'def find(db):\n    db.execute(f"DELETE FROM posts WHERE id = {request.args.get(\'id\')}")',
        "def search(request, cursor):\n    cursor.execute('SELECT * FROM t WHERE q = ' + request.GET['q'])",
        FLASK_APP + "def raw(User):\n    return User.objects.raw('SELECT * FROM auth_user WHERE name = ' + request.args['n'])",
    ], [
        FLASK_APP + "def find(cur):\n    cur.execute('SELECT * FROM users WHERE id = %s', (request.args['id'],))",
        FLASK_APP + "def find(cur):\n    cur.execute('SELECT * FROM users WHERE id = ' + str(int(request.args['id'])))",
        FLASK_APP + "def find(cur):\n    cur.execute('SELECT * FROM users WHERE id = ?', [request.args.get('id')])",
    ]),
    'py-sql-formatted-query': ([
        'def find_user(conn, name):\n    return conn.execute("SELECT * FROM users WHERE name = \'%s\'" % name).fetchall()',
        'def find_order(cursor, order_id):\n    cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
        "def rename(cur, new, old):\n    cur.execute('UPDATE users SET name = {} WHERE name = {}'.format(new, old))",
        "def remove(cur, ids):\n    cur.executemany('DELETE FROM t WHERE id = ' + ids, [])",
    ], [
        "def find(cur, user_id):\n    cur.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "def find(cur):\n    cur.execute('SELECT * FROM users')",
        "def find(cur):\n    cur.execute(f'SELECT * FROM users')",
        "def find(cur):\n    cur.execute('SELECT * FROM users ' + 'ORDER BY id')",
        "def log(logger, name):\n    logger.info('select %s' % name)",
    ]),
    'py-path-traversal': ([
        FLASK_APP + "@app.route('/file')\ndef download():\n    return open('/srv/files/' + request.args['name']).read()",
        FLASK_APP + "import os\nfrom flask import send_file\ndef get():\n    return send_file(os.path.join('/srv/uploads', request.args.get('f')))",
        "def view(request):\n    with open(request.GET['path']) as fh:\n        return fh.read()",
    ], [
        FLASK_APP + "import os\ndef download():\n    return open(os.path.join('/srv/files', os.path.basename(request.args['name']))).read()",
        FLASK_APP + "from werkzeug.utils import secure_filename\ndef save():\n    open('/srv/up/' + secure_filename(request.files['f'].filename), 'wb')",
        FLASK_APP + "from flask import send_from_directory\ndef get():\n    return send_from_directory('/srv/files', request.args['name'])",
        "def read(name):\n    return open('/srv/files/' + name).read()",
    ]),
    'py-ssrf': ([
        FLASK_APP + "import requests\ndef proxy():\n    return requests.get(request.args['url']).text",
        FLASK_APP + "import urllib.request\ndef fetch():\n    url = request.form['target']\n    return urllib.request.urlopen(url).read()",
        FLASK_APP + "import httpx\ndef hook():\n    httpx.post(request.json['callback'], json={})",
        FLASK_APP + "import requests\ndef go():\n    requests.request('GET', request.args.get('u'))",
    ], [
        FLASK_APP + "import requests\ndef user():\n    return requests.get('https://api.example.com/users/' + request.args['id']).text",
        FLASK_APP + 'import requests\ndef user():\n    return requests.get(f"https://api.example.com/users/{request.args[\'id\']}").text',
        FLASK_APP + "import requests\ndef status():\n    return requests.get('https://status.example.com', params={'q': request.args['q']}).text",
        'import requests\ndef fetch(url):\n    return requests.get(url).text',
        "import requests\ndef notify(request, Webhook):\n    hook = Webhook.objects.get(pk=request.POST['id'])\n    requests.post(hook.url, json={})",
    ]),
    'py-xss': ([
        FLASK_APP + "@app.route('/hello')\ndef hello():\n    return '<h1>Hello ' + request.args.get('name') + '</h1>'",
        FLASK_APP + "@app.get('/q')\ndef q():\n    term = request.args['q']\n    return f'<p>Results for {term}</p>'",
        FLASK_APP + "from flask import render_template_string\n@app.route('/t')\ndef t():\n    return render_template_string('Hi ' + request.args['n'])",
        "from django.http import HttpResponse\ndef echo(request):\n    return HttpResponse('You said ' + request.GET['msg'])",
        FLASK_APP + "from markupsafe import Markup\ndef note():\n    return Markup('<b>%s</b>' % request.form['note'])",
    ], [
        FLASK_APP + "from markupsafe import escape\n@app.route('/hello')\ndef hello():\n    return '<h1>Hello ' + escape(request.args.get('name')) + '</h1>'",
        FLASK_APP + "from flask import render_template\n@app.route('/hello')\ndef hello():\n    return render_template('hello.html', name=request.args['name'])",
        FLASK_APP + "from flask import jsonify\n@app.route('/api')\ndef api():\n    return jsonify(name=request.args['name'])",
        FLASK_APP + "@app.route('/api')\ndef api():\n    return {'name': request.args['name']}",
        FLASK_APP + "from flask import redirect\n@app.route('/go')\ndef go():\n    return redirect('/home?ref=' + request.args['ref'])",
        FLASK_APP + "def helper():\n    return '<b>' + request.args['x'] + '</b>'",
    ]),
    'py-weak-password-hash': ([
        'import hashlib\ndef store(password):\n    return hashlib.md5(password.encode()).hexdigest()',
        'import hashlib\ndef sign(secret, body):\n    return hashlib.sha1(secret + body).hexdigest()',
        'import hashlib\ndef check(user):\n    return hashlib.sha1(user.pwd_plain.encode()).digest()',
    ], [
        "import hashlib\ndef store(password, salt):\n    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)",
        'import hmac, hashlib\ndef sign(secret, body):\n    return hmac.new(secret, body, hashlib.sha1).hexdigest()',
    ]),
}

JAVASCRIPT_CASES = {
    'js-dangerous-eval': ([
        'const total = eval(req.body.preTax);',
        'eval(`${a} + ${b}`);',
        'eval(code); // nosemgrep',   # suppression comments in scanned code are ignored
    ], [
        'eval("1 + 1");',
        'redis.eval(script, 0);',
        'const total = JSON.parse(req.body.preTax);',
    ]),
    'js-implied-eval': ([
        'const f = new Function("a", body);',
        'const f = Function(userCode);',
        'setTimeout("refresh(" + id + ")", 100);',
        'setInterval(`poll(${id})`, 100);',
        'window.setTimeout("go(" + x + ")", 5);',
    ], [
        'const f = new Function("a", "b", "return a + b");',
        'const f = new Function(`return 1`);',
        'setTimeout(() => refresh(id), 100);',
        'setTimeout(refresh, 100);',
    ]),
    'js-vm-dynamic-code': ([
        "const vm = require('vm');\nvm.runInNewContext(req.body.code, sandbox);",
        "const vm = require('node:vm');\nvm.runInContext(code, context);",
        "const vm = require('vm');\nconst script = new vm.Script(source);",
    ], [
        "const vm = require('vm');\nvm.runInNewContext('1 + 1', sandbox);",
    ]),
    'js-child-process-exec': ([
        "const cp = require('child_process');\ncp.exec('ls ' + dir);",
        "const { execSync } = require('child_process');\nexecSync(`git log ${ref}`);",
        "var exec = require('child_process').exec;\nexec(cmd + ' --force', done);",
        "import { exec } from 'node:child_process';\nexec(command);",
        "import * as cp from 'child_process';\ncp.execSync(command);",
        "require('child_process').exec(userInput);",
    ], [
        "const cp = require('child_process');\ncp.exec('ls -la');",
        "const cp = require('child_process');\ncp.exec(`ls -la`);",
        "const cp = require('child_process');\ncp.execFile('git', ['log', ref]);",
        "const db = require('./db');\ndb.exec(query);",
        "const pattern = /a/;\npattern.exec(input);",
    ]),
    'js-insecure-deserialization-node-serialize': ([
        "const serialize = require('node-serialize');\nconst obj = serialize.unserialize(req.cookies.profile);",
        "import { unserialize } from 'node-serialize';\nunserialize(data);",
    ], [
        "const serialize = require('node-serialize');\nconst text = serialize.serialize(obj);",
        "const qs = require('querystring');\nqs.unescape(data);",
    ]),
    'js-weak-hash': ([
        "const crypto = require('crypto');\ncrypto.createHash('md5').update(data);",
        "const crypto = require('crypto');\ncrypto.createHash('SHA1');",
        "const crypto = require('crypto');\nconst etag = crypto.createHash('md5').update(body).digest('hex');",
    ], [
        "const crypto = require('crypto');\ncrypto.createHash('sha256').update(data);",
    ]),
    'js-math-random-for-secrets': ([
        'const resetToken = Math.random().toString(36).slice(2);',
        'user.password = Math.floor(Math.random() * 1e8).toString();',
        'const session = { sessionId: Math.random().toString(16) };',
        'const otp = Math.floor(100000 + Math.random() * 900000);',
        'function generateToken() {\n  return Math.random().toString(36);\n}',
    ], [
        'const stocks = Math.floor((Math.random() * 40) + 1);',   # NodeGoat's sample portfolio
        'const tokenIndex = Math.floor(Math.random() * tokens.length);',
        'const footprint = Math.random();',
        "const resetToken = crypto.randomBytes(32).toString('hex');",
    ]),
    'js-tls-verification-disabled': ([
        'https.request({ host, rejectUnauthorized: false });',
        'const options = { tls: { rejectUnauthorized: false } };',
        'agent.options.rejectUnauthorized = false;',
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
        "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';",
    ], [
        'https.request({ host, rejectUnauthorized: true });',
        "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';",
    ]),
    'js-cookie-without-httponly': ([
        "res.cookie('sid', id, { httpOnly: false });",
        'app.use(session({ secret: process.env.S, cookie: { httpOnly: false } }));',
    ], [
        "res.cookie('sid', id, { httpOnly: true, secure: true });",
    ]),
    'js-cookie-without-secure': ([
        "res.cookie('sid', id, { httpOnly: true, secure: false });",
        'app.use(session({ secret: process.env.S, cookie: { secure: false } }));',
        "app.use(cookieSession({ name: 's', keys: [process.env.K], secure: false }));",
        # express-session leaves secure off unless the inline options set it.
        "const session = require('express-session');\napp.use(session({ secret: process.env.S, resave: false }));",
        "const session = require('express-session');\napp.use(session({ secret: process.env.S, cookie: { httpOnly: true } }));",
        "import session from 'express-session';\napp.use(session({ secret: process.env.S }));",
    ], [
        'const transport = nodemailer.createTransport({ host, port: 587, secure: false });',
        "const session = require('express-session');\napp.use(session({ secret: process.env.S, cookie: { secure: true } }));",
        "const session = require('express-session');\napp.use(session({ secret: process.env.S, cookie: { secure: isProd } }));",
        "const session = require('express-session');\napp.use(session({ secret: process.env.S, cookie: cookieOptions }));",
        # The express-session README's pattern: options built first, secure set for production.
        "const session = require('express-session');\nconst sess = { secret: process.env.S, cookie: {} };\n"
        "if (prod) sess.cookie.secure = true;\napp.use(session(sess));",
        "const session = require('koa-session');\napp.use(session({ key: 'k' }, app));",
    ]),
    'js-template-autoescape-disabled': ([
        'swig.setDefaults({ autoescape: false });',
        "nunjucks.configure('views', { autoescape: false, express: app });",
        'const template = Handlebars.compile(source, { noEscape: true });',
    ], [
        "nunjucks.configure('views', { autoescape: true });",
        'const template = Handlebars.compile(source, { noEscape: false });',
    ]),
    'js-nosql-injection': ([
        "return { $where: `this.userId == ${id} && this.stocks > '${threshold}'` };",
        "users.find({ $where: 'this.age > ' + age });",
        'users.findOne({ userName: req.body.userName, password: req.body.password }, cb);',
        'users.find(req.query);',
        "users.findOne({ _id: req.query['id'] });",
        'users.update({ _id: req.body.id }, { $set: { name: name } });',
    ], [
        "users.find({ $where: 'this.age > 18' });",
        'users.find({ $where: function () { return this.age > 18; } });',
        'users.findOne({ _id: parseInt(req.params.id) });',
        'users.findOne({ userName: String(req.body.userName) });',
        'items.find(item => item.id === req.query.id);',
        'hash.update(req.body.data);',
    ]),
    'js-open-redirect': ([
        'return res.redirect(req.query.url);',
        'res.redirect(302, req.body.next);',
        "res.redirect(req.param('target'));",
        "res.redirect(req.query.next + '?ok=1');",
    ], [
        "res.redirect('/user/' + req.params.id);",
        'res.redirect(`/user/${req.params.id}`);',
        "res.redirect('/login');",
    ]),
    'js-hardcoded-session-secret': ([
        "app.use(session({ secret: 'keyboard cat', resave: false }));",
        "app.use(expressSession({ secret: ['a', process.env.B] }));",
        "app.use(cookieSession({ name: 'session', keys: ['key1', 'key2'] }));",
        "app.use(cookieParser('my secret'));",
        "module.exports = { cookieSecret: 'session_cookie_secret_key_here' };",
        "const config = { sessionSecret: process.env.SESSION_SECRET || 'dev-secret' };",
    ], [
        'app.use(session({ secret: process.env.SESSION_SECRET, resave: false }));',
        'app.use(cookieParser(process.env.COOKIE_SECRET));',
        'app.use(cookieParser());',
        "const { cookieSecret } = require('./config');\napp.use(session({ secret: cookieSecret }));",
    ]),
    'js-sql-injection': ([
        # Also a formatted query: the runner keeps only the more severe finding for the line.
        EXPRESS_APP + "app.get('/search', (req, res) => {\n  const criteria = req.query.q;\n  db.query(`SELECT * FROM products WHERE name LIKE '%${criteria}%'`, (e, rows) => res.json(rows));\n});",
        EXPRESS_APP + 'app.get(\'/user\', (req, res) => db.query("SELECT * FROM users WHERE id = " + req.query.id, (e, rows) => res.json(rows)));',
        EXPRESS_APP + "app.post('/find', async (req, res) => {\n  const sql = `SELECT * FROM users WHERE name = '${req.body.name}'`;\n  const rows = await pool.query(sql);\n  res.json(rows);\n});",
        EXPRESS_APP + "app.get('/raw', async (req, res) => res.json(await prisma.$queryRawUnsafe('SELECT * FROM t WHERE a = ' + req.params.a)));",
        "export async function GET(request) {\n  return Response.json(await db.query('SELECT * FROM users WHERE id = ' + request.headers.get('x-user')));\n}",
        EXPRESS_APP + "app.get('/k', async (req, res) => res.json(await knex.raw(`DELETE FROM t WHERE id = ${req.query.id}`)));",
    ], [
        EXPRESS_APP + "app.get('/user', (req, res) => db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (e, rows) => res.json(rows)));",
        EXPRESS_APP + "app.get('/user', (req, res) => pool.query('SELECT * FROM users WHERE id = $1', [req.params.id]).then((r) => res.json(r.rows)));",
        EXPRESS_APP + "app.get('/user', (req, res) => db.query('SELECT * FROM users WHERE id = ' + parseInt(req.query.id, 10), cb));",
        EXPRESS_APP + "app.get('/gql', async (req, res) => res.json(await client.query({ query: GET_USER, variables: { id: req.query.id } })));",
        EXPRESS_APP + "app.get('/user', (req, res) => db.query('SELECT * FROM users WHERE id = ' + connection.escape(req.query.id), cb));",
    ]),
    'js-sql-formatted-query': ([
        "async function find(pool, name) {\n  return pool.query(`SELECT * FROM users WHERE name = '${name}'`);\n}",
        "function remove(db, id, cb) {\n  db.query('DELETE FROM posts WHERE id = ' + id, cb);\n}",
    ], [
        "async function find(pool, name) {\n  return pool.query('SELECT * FROM users WHERE name = $1', [name]);\n}",
        'async function all(pool) {\n  return pool.query(`SELECT * FROM users`);\n}',
        "function find(db, cb) {\n  db.query('SELECT * FROM users ' + 'ORDER BY id', cb);\n}",
        "const params = new URLSearchParams(location.search);\nconst q = params.get('query');",
    ]),
    'js-path-traversal': ([
        EXPRESS_APP + "const fs = require('fs');\napp.get('/file', (req, res) => res.send(fs.readFileSync('/srv/files/' + req.query.name)));",
        EXPRESS_APP + "const path = require('path');\napp.get('/dl', (req, res) => res.sendFile(path.join(__dirname, 'files', req.params.file)));",
        EXPRESS_APP + "const fs = require('fs');\napp.get('/s', (req, res) => fs.createReadStream(req.query.p).pipe(res));",
        EXPRESS_APP + "app.get('/d', (req, res) => res.download('/srv/files/' + req.query.f));",
        EXPRESS_APP + "const fs = require('fs');\napp.get('/u/:id', (req, res) => User.findById(req.params.id, (err, user) => res.send(fs.readFileSync('/srv/' + req.query.p))));",
        EXPRESS_APP + "const fs = require('fs');\napp.post('/up', (req, res) => {\n  fs.writeFileSync('uploads/' + req.file.originalname, req.file.buffer);\n  res.sendStatus(201);\n});",
    ], [
        EXPRESS_APP + "const fs = require('fs');\nconst path = require('path');\napp.get('/file', (req, res) => res.send(fs.readFileSync(path.join('/srv/files', path.basename(req.query.name)))));",
        EXPRESS_APP + "app.get('/dl', (req, res) => res.sendFile(req.params.file, { root: '/srv/files' }));",
        "const fs = require('fs');\nfunction load(name) {\n  return fs.readFileSync('/srv/files/' + name);\n}",
        EXPRESS_APP + "app.get('/files/:file(*)', (req, res) => res.download(req.params.file, { root: '/srv/files' }));",
        EXPRESS_APP + "const fs = require('fs');\napp.get('/avatar', (req, res) => {\n  const user = sessions.get(req.cookies.token);\n  res.send(fs.readFileSync(`avatars/${user.id}.png`));\n});",
        EXPRESS_APP + "const fs = require('fs/promises');\nconst { fileTypeFromBuffer } = require('file-type');\napp.post('/avatar', async (req, res) => {\n  const type = await fileTypeFromBuffer(req.file.buffer);\n  await fs.writeFile(`uploads/${req.user.id}.${type.ext}`, req.file.buffer);\n  res.sendStatus(204);\n});",
    ]),
    'js-ssrf': ([
        EXPRESS_APP + "const axios = require('axios');\napp.get('/fetch', async (req, res) => res.send((await axios.get(req.query.url)).data));",
        EXPRESS_APP + "const needle = require('needle');\napp.get('/r', (req, res) => {\n  const url = req.query.url + req.query.symbol;\n  return needle.get(url, (e, r, body) => res.json(body));\n});",
        EXPRESS_APP + "app.post('/hook', async (req, res) => {\n  await fetch(req.body.callback, { method: 'POST' });\n  res.sendStatus(204);\n});",
        EXPRESS_APP + "const https = require('https');\napp.get('/p', (req, res) => https.get(req.query.target, (r) => r.pipe(res)));",
    ], [
        EXPRESS_APP + "const axios = require('axios');\napp.get('/user', async (req, res) => res.json((await axios.get('https://api.example.com/users/' + req.params.id)).data));",
        EXPRESS_APP + "app.get('/user', async (req, res) => res.json(await (await fetch(`https://api.example.com/users/${req.query.id}`)).json()));",
        "const axios = require('axios');\nasync function load(url) {\n  return (await axios.get(url)).data;\n}",
        EXPRESS_APP + "app.post('/ping/:id', async (req, res) => {\n  const hook = await Webhook.findById(req.params.id);\n  await fetch(hook.url);\n  res.sendStatus(204);\n});",
        EXPRESS_APP + "const axios = require('axios');\napp.get('/s', async (req, res) => res.json((await axios.get('https://api.example.com/search', { params: { q: req.query.q } })).data));",
    ]),
    'js-xss': ([
        EXPRESS_APP + "app.get('/hello', (req, res) => res.send('<h1>Hello ' + req.query.name + '</h1>'));",
        EXPRESS_APP + "app.get('/q', (req, res) => {\n  const term = req.query.q;\n  res.status(200).send(`<p>Results for ${term}</p>`);\n});",
        EXPRESS_APP + "app.post('/echo', (req, res) => {\n  res.write(req.body.message);\n  res.end();\n});",
    ], [
        EXPRESS_APP + "const escapeHtml = require('escape-html');\napp.get('/hello', (req, res) => res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>'));",
        EXPRESS_APP + "app.get('/api', (req, res) => res.json({ name: req.query.name }));",
        EXPRESS_APP + "app.get('/api', (req, res) => res.send({ name: req.query.name }));",
        EXPRESS_APP + "app.get('/hello', (req, res) => res.render('hello', { name: req.query.name }));",
        EXPRESS_APP + "app.get('/n', (req, res) => res.send('Page ' + Number(req.query.page)));",
        'function reply(ws, msg) {\n  ws.send(msg);\n}',
        EXPRESS_APP + "const users = { 1: { name: 'tobi' } };\napp.get('/users/:id', (req, res) => res.send(users[req.params.id] || { error: 'not found' }));",
        EXPRESS_APP + "app.get('/echo', (req, res) => res.send(req.query));",
    ]),
    'js-weak-password-hash': ([
        "const crypto = require('crypto');\nconst hash = crypto.createHash('md5').update(password).digest('hex');",
        "const crypto = require('crypto');\nfunction sign(body) {\n  return crypto.createHash('sha1').update(process.env.API_SECRET + body).digest('hex');\n}",
        "const crypto = require('crypto');\nconst h = crypto.createHash('SHA1').update(req.body.newPassword).digest('base64');",
    ], [
        "const crypto = require('crypto');\nconst key = crypto.scryptSync(password, salt, 64);",
        "const crypto = require('crypto');\nconst mac = crypto.createHmac('sha1', secret).update(body).digest('hex');",
    ]),
}

# Every supported extension is parsed and scanned, and each language's rules stay in their language.
EXTENSIONS = {
    'case.js': ('eval(code);', {'js-dangerous-eval'}),
    'case.jsx': ('const V = () => <div>{eval(code)}</div>;', {'js-dangerous-eval'}),
    'case.mjs': ('export const run = (code) => eval(code);', {'js-dangerous-eval'}),
    'case.cjs': ('module.exports = (code) => eval(code);', {'js-dangerous-eval'}),
    'case.ts': ('const run = (code: string): unknown => eval(code);', {'js-dangerous-eval'}),
    'case.tsx': ('const V = (p: { c: string }) => <b>{eval(p.c)}</b>;', {'js-dangerous-eval'}),
    'case.py': ('eval(code)', {'py-dangerous-eval'}),
}


def scan(tmp_path, monkeypatch, sources):
    """Write {name: source}, scan them all at once, return {name: {rule ids}}."""
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    for name, source in sources.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(source + '\n')
    rules = tmp_path.parent / f'{tmp_path.name}-rules.yaml'
    rules.write_text(OFFLINE_RULESET)
    found = {name: set() for name in sources}
    for f in run_semgrep(sorted(sources), str(tmp_path), config=str(rules)):
        found[f['path']].add(f['rule_id'])
    return found


def test_ruleset_counts_and_metadata():
    ids = [rule['id'] for rule in RULES]
    assert len(ids) == len(set(ids)) == 41
    assert sum(rule['languages'] == ['python'] for rule in RULES) == 21
    assert len(JAVASCRIPT_RULES) == 20 and all(rule.startswith('js-') for rule in JAVASCRIPT_RULES)
    for rule in RULES:
        assert rule['severity'] in {'ERROR', 'WARNING'} and rule['metadata']['cwe'].startswith('CWE-'), rule['id']
        if rule['id'] in JAVASCRIPT_RULES:
            assert rule['metadata']['owasp'].endswith(':2021'), rule['id']
    readme = (Path(__file__).resolve().parent.parent / 'README.md').read_text()
    assert '41 service-owned rules' in readme


def test_every_rule_has_positive_and_negative_examples(tmp_path, monkeypatch):
    assert set(PYTHON_CASES) == PYTHON_RULES and set(JAVASCRIPT_CASES) == JAVASCRIPT_RULES
    sources, expected = {}, {}
    for rule, (positives, negatives) in {**PYTHON_CASES, **JAVASCRIPT_CASES}.items():
        assert positives and negatives, rule
        extension = '.py' if rule in PYTHON_RULES else '.js'
        for kind, snippets in (('match', positives), ('clean', negatives)):
            for index, source in enumerate(snippets):
                name = f'{rule}/{kind}_{index}{extension}'
                sources[name], expected[name] = source, ({rule} if kind == 'match' else set())
    found = scan(tmp_path, monkeypatch, sources)
    assert {name: (sources[name], rules) for name, rules in found.items()} == \
           {name: (sources[name], rules) for name, rules in expected.items()}


def test_every_supported_extension_is_scanned_by_its_own_language(tmp_path, monkeypatch):
    found = scan(tmp_path, monkeypatch, {name: source for name, (source, _) in EXTENSIONS.items()})
    assert found == {name: rules for name, (_, rules) in EXTENSIONS.items()}


@pytest.mark.parametrize('name, source, line', [
    # Object properties are reported on their own line, not where the object starts.
    ('config.js', "module.exports = {\n  port,\n  cookieSecret: 'not-a-real-secret',\n};", 3),
    ('dao.js', "const criteria = () => {\n  return {\n    $where: `this.stocks > '${threshold}'`\n  };\n};", 3),
    ('server.js', "https.request({\n  host,\n  rejectUnauthorized: false,\n});", 3),
])
def test_findings_point_at_the_offending_line(tmp_path, monkeypatch, name, source, line):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    (tmp_path / 'repo').mkdir()
    (tmp_path / 'repo' / name).write_text(source + '\n')
    rules = tmp_path / 'rules.yaml'
    rules.write_text(OFFLINE_RULESET)
    [finding] = run_semgrep([name], str(tmp_path / 'repo'), config=str(rules))
    assert (finding['start_line'], finding['end_line']) == (line, line)


def test_files_in_folders_semgrep_ignores_by_default_are_still_scanned(tmp_path, monkeypatch):
    # Without the runner's empty .semgrepignore, Semgrep's built-in defaults
    # would skip these folders and the scan would fail closed.
    folders = ['tests', 'test', 'vendor', 'build', 'dist', 'node_modules/pkg']
    sources = {f'{folder}/case.js': 'eval(code);' for folder in folders}
    sources['tests/test_case.py'] = 'eval(code)'
    found = scan(tmp_path, monkeypatch, sources)
    assert found == {name: {'py-dangerous-eval' if name.endswith('.py') else 'js-dangerous-eval'} for name in sources}


# A pull request, scanned for real and triaged against its diff: (old source, new source).
PULL_REQUEST = {
    'reports.py': (
        'import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n',
        'import hashlib\nimport random\nimport subprocess\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n'
        '\n\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n'
        '\n\ndef reset_code():\n    return str(random.randint(100000, 999999))\n'),
    'tests/test_reports.py': (
        'import tempfile\n\n\ndef scratch():\n    return tempfile.mktemp()\n',
        'import pickle\nimport tempfile\n\n\ndef load(blob):\n    return pickle.loads(blob)\n'
        '\n\ndef scratch():\n    return tempfile.mktemp()\n'),
    'routes/learn.js': (
        'app.get("/learn", (req, res) => res.redirect(req.query.url));\n',
        'app.get("/learn", (req, res) => res.redirect(req.query.url));\n'
        'app.post("/total", (req, res) => res.json(eval(req.body.total)));\n'),
    '__tests__/learn.test.js': ('', 'test("total", () => expect(eval(fixture)).toBe(2));\n'),
}
PULL_REQUEST_TRIAGE = {
    ('reports.py', 'py-subprocess-shell-true'): ('P1', True),                       # fails the check
    ('reports.py', 'py-weak-md5'): ('P2', False),                                   # medium, already there: notice
    ('reports.py', 'py-random-for-secrets'): ('P2', True),                          # medium in runtime code
    ('tests/test_reports.py', 'py-insecure-deserialization-pickle-loads'): ('P2', True),   # high in test code
    ('tests/test_reports.py', 'py-tempfile-mktemp'): ('P3', False),                 # medium in test code
    ('routes/learn.js', 'js-dangerous-eval'): ('P1', True),
    ('routes/learn.js', 'js-open-redirect'): ('P2', False),
    ('__tests__/learn.test.js', 'js-dangerous-eval'): ('P2', True),                 # JavaScript test naming
}


def patch(old, new):
    """GitHub's `patch` field: the unified diff's hunks without file headers."""
    rows = difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm='')
    return '\n'.join(list(rows)[2:])


def test_a_pull_request_is_scanned_and_triaged_against_its_diff(tmp_path, monkeypatch):
    monkeypatch.setenv('PRSEC_MODE', 'local')
    monkeypatch.setenv('PRSEC_SCANNER_BACKEND', 'local')
    for name, (_, source) in PULL_REQUEST.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(source)
    rules = tmp_path.parent / f'{tmp_path.name}-rules.yaml'
    rules.write_text(OFFLINE_RULESET)
    findings = triage(run_semgrep(sorted(PULL_REQUEST), str(tmp_path), config=str(rules)),
                      {name: added_lines(patch(old, new)) for name, (old, new) in PULL_REQUEST.items()})
    assert {(f['path'], f['rule_id']): (f['priority'], f['new']) for f in findings} == PULL_REQUEST_TRIAGE
    assert gate(findings) == 'failure'
    assert [f['priority'] for f in findings] == sorted(f['priority'] for f in findings)
