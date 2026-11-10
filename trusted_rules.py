"""Service-owned Semgrep rules for Python, JavaScript and TypeScript: the only rules any scan uses."""
OFFLINE_RULESET = r"""
rules:
  # Crypto: weak hashes
  - id: py-weak-md5
    message: Use of weak hash (md5)
    severity: WARNING
    languages: [python]
    pattern-either:
      - pattern: hashlib.md5()
      - patterns:
          - pattern: hashlib.md5($DATA, ...)
          # Not for security (a cache key, say), or a password: py-weak-password-hash.
          - pattern-not: hashlib.md5(..., usedforsecurity=False, ...)
          - metavariable-regex:
              metavariable: $DATA
              regex: (?is)^(?!.*(passw|pwd|passphrase|secret))
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  - id: py-weak-sha1
    message: Use of weak hash (sha1)
    severity: WARNING
    languages: [python]
    pattern-either:
      - pattern: hashlib.sha1()
      - patterns:
          - pattern: hashlib.sha1($DATA, ...)
          # Not for security (a cache key, say), or a password: py-weak-password-hash.
          - pattern-not: hashlib.sha1(..., usedforsecurity=False, ...)
          - metavariable-regex:
              metavariable: $DATA
              regex: (?is)^(?!.*(passw|pwd|passphrase|secret))
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  # YAML / Deserialization
  - id: py-unsafe-yaml-load
    message: yaml.load without a safe loader
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: yaml.load(...)
      - pattern-not: yaml.load(..., Loader=yaml.SafeLoader)
      - pattern-not: yaml.load(..., Loader=SafeLoader)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-unsafe-yaml-unsafe-load
    message: yaml.unsafe_load used
    severity: ERROR
    languages: [python]
    pattern: yaml.unsafe_load(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-insecure-deserialization-pickle-loads
    message: Insecure deserialization via pickle.loads
    severity: ERROR
    languages: [python]
    pattern: pickle.loads(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  - id: py-insecure-deserialization-pickle-load
    message: Insecure deserialization via pickle.load
    severity: ERROR
    languages: [python]
    pattern: pickle.load(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  # Command Execution
  - id: py-os-system
    message: os.system() can lead to command injection
    severity: ERROR
    languages: [python]
    pattern: os.system(...)
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-os-popen
    message: os.popen*() can lead to command injection
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: os.popen(...)
      - pattern: os.popen2(...)
      - pattern: os.popen3(...)
      - pattern: os.popen4(...)
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-subprocess-shell-true
    message: subprocess with shell=True (possible injection)
    severity: ERROR
    languages: [python]
    patterns:
      - pattern: subprocess.$F(..., shell=True, ...)
      - metavariable-pattern:
          metavariable: $F
          pattern-either:
            - pattern: run
            - pattern: call
            - pattern: Popen
            - pattern: check_output
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  - id: py-dangerous-eval
    message: Dangerous use of eval()
    severity: ERROR
    languages: [python]
    pattern: eval(...)
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  - id: py-dangerous-exec
    message: Dangerous use of exec()
    severity: ERROR
    languages: [python]
    pattern: exec(...)
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  # HTTP / TLS
  - id: py-requests-disable-verify
    message: TLS certificate verification disabled
    severity: ERROR
    languages: [python]
    pattern: requests.$F(..., verify=False, ...)
    metadata:
      cwe: CWE-295
      owasp: A02:2021

  # Randomness / temp files
  - id: py-random-for-secrets
    message: random module is not cryptographically secure
    severity: WARNING
    languages: [python]
    pattern: random.$F(...)
    metadata:
      cwe: CWE-338

  - id: py-tempfile-mktemp
    message: tempfile.mktemp() is insecure; use NamedTemporaryFile/mkstemp
    severity: WARNING
    languages: [python]
    pattern: tempfile.mktemp(...)
    metadata:
      cwe: CWE-377

  # Archives (handle direct and context-manager forms)
  - id: py-tarfile-extractall
    message: tarfile.extractall() can allow path traversal
    severity: ERROR
    languages: [python]
    pattern-either:
      - pattern: tarfile.extractall(...)
      - pattern: tarfile.open(...).extractall(...)
      - pattern: |
          with tarfile.open(...) as $TF:
            ...
            $TF.extractall(...)
    metadata:
      cwe: CWE-22


  # Request data reaching a dangerous call (taint mode: followed within one file).
  # Only data from the request itself: a value looked up with it, or a number parsed from it, is not.
  - id: py-sql-injection
    message: SQL query built from request data (SQL injection); pass values as query parameters
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources: &py-request
      - patterns:
          - pattern-either:
              - pattern: request.$ATTR
              - pattern: flask.request.$ATTR
          - metavariable-regex:
              metavariable: $ATTR
              regex: ^(args|form|values|json|cookies|headers|data|files|view_args|get_json|get_data|GET|POST|COOKIES|body|META)$
    pattern-sinks:
      - patterns:
          - pattern: $DB.$METHOD($QUERY, ...)
          - metavariable-regex:
              metavariable: $METHOD
              regex: ^(execute|executemany|executescript|raw|exec_driver_sql)$
          - focus-metavariable: $QUERY
      - patterns:
          - pattern-either:
              - pattern: text($QUERY, ...)
              - pattern: sqlalchemy.text($QUERY, ...)
          - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern-either:
          - pattern: int(...)
          - pattern: float(...)
      # A record looked up with request data (User.objects.get(pk=...)) is stored data, not the request's.
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern-either:
                      - pattern: $MODEL.objects.$LOOKUP(...)
                      - pattern: $MODEL.query.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(get|get_or_404|first_or_404|filter|filter_by|first|get_or_create)$
              - pattern: get_object_or_404(...)
              - pattern: $DB.session.get(...)
        exact: true
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: py-sql-formatted-query
    message: SQL query built with string formatting; pass values as query parameters
    severity: WARNING
    languages: [python]
    patterns:
      - pattern-either:
          - patterns:
              - pattern-either:
                  - pattern: $DB.$METHOD("$SQL" % $X, ...)
                  - pattern: $DB.$METHOD("$SQL".format(...), ...)
                  - pattern: $DB.$METHOD("$SQL" + $X, ...)
              - metavariable-regex:
                  metavariable: $SQL
                  regex: (?is).*\b(select|insert|update|delete|replace)\b
              - pattern-not: $DB.$METHOD("..." + "...", ...)
          - patterns:
              - pattern: $DB.$METHOD($QUERY, ...)
              - metavariable-pattern:
                  metavariable: $QUERY
                  pattern: f"..."
              - metavariable-regex:
                  metavariable: $QUERY
                  regex: (?is).*\b(select|insert|update|delete|replace)\b.*\{
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^(execute|executemany|executescript|raw|exec_driver_sql)$
      # Request data in the query is py-sql-injection's finding.
      - pattern-not: $DB.$METHOD(<... request.$ATTR ...>, ...)
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: py-path-traversal
    message: File path built from request data (path traversal); use os.path.basename or werkzeug's secure_filename
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources: *py-request
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: open($PATH, ...)
              - pattern: io.open($PATH, ...)
              - pattern: codecs.open($PATH, ...)
              - pattern: send_file($PATH, ...)
              - pattern: flask.send_file($PATH, ...)
          - focus-metavariable: $PATH
    pattern-sanitizers:
      - pattern-either:
          - pattern: os.path.basename(...)
          - pattern: secure_filename(...)
          - pattern: werkzeug.utils.secure_filename(...)
          - pattern: int(...)
      # A record looked up with request data (User.objects.get(pk=...)) is stored data, not the request's.
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern-either:
                      - pattern: $MODEL.objects.$LOOKUP(...)
                      - pattern: $MODEL.query.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(get|get_or_404|first_or_404|filter|filter_by|first|get_or_create)$
              - pattern: get_object_or_404(...)
              - pattern: $DB.session.get(...)
        exact: true
    metadata:
      cwe: CWE-22
      owasp: A01:2021

  - id: py-ssrf
    message: Outgoing request to a URL taken from request data (server-side request forgery)
    severity: ERROR
    languages: [python]
    mode: taint
    pattern-sources: *py-request
    pattern-sinks:
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern-either:
                      - pattern: requests.$METHOD($URL, ...)
                      - pattern: httpx.$METHOD($URL, ...)
                  - metavariable-regex:
                      metavariable: $METHOD
                      regex: ^(get|post|put|patch|delete|head|options)$
              - pattern: requests.request($M, $URL, ...)
              - pattern: httpx.request($M, $URL, ...)
              - pattern: urllib.request.urlopen($URL, ...)
              - pattern: urlopen($URL, ...)
          - focus-metavariable: $URL
    pattern-sanitizers:
      # A URL that starts with a fixed scheme and host can't be pointed at another server.
      - patterns:
          - pattern: $URL
          - metavariable-pattern:
              metavariable: $URL
              pattern-either:
                - pattern: $A + $B
                - pattern: $A % $B
                - pattern: $A.format(...)
                - pattern: f"..."
          - metavariable-regex:
              metavariable: $URL
              regex: ^[rbu]*f?[rbu]*["']https?://[^/"'{}%]+/
      # A record looked up with request data (User.objects.get(pk=...)) is stored data, not the request's.
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern-either:
                      - pattern: $MODEL.objects.$LOOKUP(...)
                      - pattern: $MODEL.query.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(get|get_or_404|first_or_404|filter|filter_by|first|get_or_create)$
              - pattern: get_object_or_404(...)
              - pattern: $DB.session.get(...)
        exact: true
    metadata:
      cwe: CWE-918
      owasp: A10:2021

  - id: py-xss
    message: Request data written into an HTML response or template (cross-site scripting); escape it or use an autoescaped template
    severity: ERROR
    languages: [python]
    mode: taint
    # Only data copied, concatenated or formatted into the response: what a call returns
    # (a file's contents, a query's rows) is not the request data itself.
    options:
      taint_assume_safe_functions: true
      taint_assume_safe_indexes: true
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: request.$ATTR
              - pattern: flask.request.$ATTR
              - pattern: request.$ATTR.get(...)
              - pattern: request.$ATTR.getlist(...)
          - metavariable-regex:
              metavariable: $ATTR
              regex: ^(args|form|values|json|cookies|headers|data|files|view_args|GET|POST|COOKIES|body|META)$
      - pattern: request.get_json(...)
      - pattern: request.get_data(...)
    pattern-sinks:
      - patterns:
          - pattern-inside: |
              @$APP.$ROUTE(...)
              def $FUNC(...):
                ...
          - metavariable-regex:
              metavariable: $ROUTE
              regex: ^(route|get|post|put|patch|delete)$
          - pattern: return $BODY
          # A dict or list is sent as JSON.
          - pattern-not: return {...}
          - pattern-not: return [...]
          - focus-metavariable: $BODY
      - patterns:
          - pattern-either:
              - pattern: make_response($BODY, ...)
              - pattern: flask.make_response($BODY, ...)
              - pattern: HttpResponse($BODY, ...)
              - pattern: Markup($BODY, ...)
              - pattern: markupsafe.Markup($BODY, ...)
              - pattern: render_template_string($BODY, ...)
              - pattern: flask.render_template_string($BODY, ...)
          - focus-metavariable: $BODY
    pattern-sanitizers:
      - pattern-either:
          - pattern: escape(...)
          - pattern: html.escape(...)
          - pattern: markupsafe.escape(...)
          - pattern: flask.escape(...)
          - pattern: jsonify(...)
          - pattern: flask.jsonify(...)
          - pattern: render_template(...)
          - pattern: flask.render_template(...)
          - pattern: redirect(...)
          - pattern: url_for(...)
          - pattern: int(...)
          - pattern: float(...)
    metadata:
      cwe: CWE-79
      owasp: A03:2021

  - id: py-weak-password-hash
    message: Password or secret hashed with md5 or sha1; use a password hash (bcrypt, scrypt, argon2) or HMAC-SHA256
    severity: ERROR
    languages: [python]
    patterns:
      - pattern-either:
          - pattern: hashlib.md5($DATA, ...)
          - pattern: hashlib.sha1($DATA, ...)
      - metavariable-regex:
          metavariable: $DATA
          regex: (?is).*(passw|pwd|passphrase|secret)
    metadata:
      cwe: CWE-916
      owasp: A02:2021

  # JavaScript / TypeScript: code injection
  - id: js-dangerous-eval
    message: eval() runs code built at runtime (possible code injection)
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern: eval($CODE)
      - pattern-not: eval("...")
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  - id: js-implied-eval
    message: Function constructor or string setTimeout/setInterval compiles code built at runtime
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: new Function(..., $BODY)
              - pattern: Function(..., $BODY)
          - metavariable-pattern:
              metavariable: $BODY
              patterns:
                - pattern-not: '"..."'
      - patterns:
          - pattern-either:
              - pattern: $TIMER("..." + $X, ...)
              - pattern: $TIMER($X + "...", ...)
              - pattern: $TIMER(`...${$X}...`, ...)
          - metavariable-regex:
              metavariable: $TIMER
              regex: ^(window\.)?(setTimeout|setInterval)$
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  - id: js-vm-dynamic-code
    message: vm runs code built at runtime; the vm module is not a security boundary (possible code injection)
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - patterns:
              - pattern-either:
                  - pattern: vm.$RUN($CODE, ...)
                  - pattern: require('vm').$RUN($CODE, ...)
              - metavariable-regex:
                  metavariable: $RUN
                  regex: ^(runInContext|runInNewContext|runInThisContext|compileFunction)$
          - pattern: new vm.Script($CODE, ...)
      - metavariable-pattern:
          metavariable: $CODE
          patterns:
            - pattern-not: '"..."'
    metadata:
      cwe: CWE-95
      owasp: A03:2021

  # JavaScript / TypeScript: command execution
  - id: js-child-process-exec
    message: child_process exec/execSync runs a shell command built at runtime (possible command injection)
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: require($MOD).$EXEC($CMD, ...)
          - patterns:
              - pattern-either:
                  - pattern-inside: |
                      $CP = require($MOD);
                      ...
                  - pattern-inside: |
                      import * as $CP from $MOD;
                      ...
                  - pattern-inside: |
                      import $CP from $MOD;
                      ...
              - pattern: $CP.$EXEC($CMD, ...)
          - patterns:
              - pattern-inside: |
                  $FN = require($MOD).$EXEC;
                  ...
              - pattern: $FN($CMD, ...)
          - patterns:
              - pattern-either:
                  - pattern-inside: |
                      const {..., $EXEC, ...} = require($MOD);
                      ...
                  - pattern-inside: |
                      import {..., $EXEC, ...} from $MOD;
                      ...
              - pattern: $EXEC($CMD, ...)
      - metavariable-regex:
          metavariable: $MOD
          regex: ^['"]?(node:)?child_process['"]?$
      - metavariable-regex:
          metavariable: $EXEC
          regex: ^(exec|execSync)$
      - metavariable-pattern:
          metavariable: $CMD
          patterns:
            - pattern-not: '"..."'
    metadata:
      cwe: CWE-78
      owasp: A03:2021

  # JavaScript / TypeScript: deserialization
  - id: js-insecure-deserialization-node-serialize
    message: node-serialize unserialize() can execute code embedded in the data (insecure deserialization)
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - pattern: require('node-serialize').unserialize(...)
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  $S = require('node-serialize');
                  ...
              - pattern-inside: |
                  import * as $S from 'node-serialize';
                  ...
              - pattern-inside: |
                  import $S from 'node-serialize';
                  ...
          - pattern: $S.unserialize(...)
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  const {..., unserialize, ...} = require('node-serialize');
                  ...
              - pattern-inside: |
                  import {..., unserialize, ...} from 'node-serialize';
                  ...
          - pattern: unserialize(...)
    metadata:
      cwe: CWE-502
      owasp: A08:2021

  # JavaScript / TypeScript: crypto and randomness
  - id: js-weak-hash
    message: Use of weak hash (md5 or sha1)
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - patterns:
              - pattern: $CRYPTO.createHash($ALG, ...)
              - pattern-not-inside: $CRYPTO.createHash($ALG, ...).update(...)
          # A password or secret is js-weak-password-hash's finding.
          - patterns:
              - pattern: $CRYPTO.createHash($ALG, ...).update($DATA, ...)
              - metavariable-regex:
                  metavariable: $DATA
                  regex: (?is)^(?!.*(passw|pwd|passphrase|secret))
      - metavariable-regex:
          metavariable: $ALG
          regex: (?i)^['"`](rsa-)?(md5|sha1)['"`]$
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  - id: js-math-random-for-secrets
    message: Math.random() is not cryptographically secure; use crypto.randomBytes or crypto.randomUUID for secrets
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: $NAME = <... Math.random() ...>
          - pattern: '{..., $NAME: <... Math.random() ...>, ...}'
          - pattern: |
              function $NAME(...) { ... return <... Math.random() ...>; }
      - metavariable-regex:
          metavariable: $NAME
          regex: (?i)(?!.*(index|idx|count|length|delay|timeout|interval)$).*(token|secret|passw|pwd|nonce|salt|api_?key|session_?id|csrf|xsrf|(^|[_.])otp|(verif|reset|activation|confirm)\w*code)
    metadata:
      cwe: CWE-338
      owasp: A02:2021

  # JavaScript / TypeScript: TLS, cookies and templates
  - id: js-tls-verification-disabled
    message: TLS certificate verification disabled
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern: '{..., rejectUnauthorized: $VALUE, ...}'
          - metavariable-pattern:
              metavariable: $VALUE
              pattern: 'false'
          - focus-metavariable: $VALUE
      - pattern: $OBJ.rejectUnauthorized = false
      - pattern: process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
      - pattern: process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0
      - pattern: process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0'
    metadata:
      cwe: CWE-295
      owasp: A02:2021

  - id: js-cookie-without-httponly
    message: Cookie set with httpOnly false; page scripts can read it (session theft through XSS)
    severity: WARNING
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern: '{..., httpOnly: $VALUE, ...}'
          - metavariable-pattern:
              metavariable: $VALUE
              pattern: 'false'
          - focus-metavariable: $VALUE
      - pattern: $COOKIE.httpOnly = false
    metadata:
      cwe: CWE-1004
      owasp: A05:2021

  - id: js-cookie-without-secure
    message: Cookie not marked secure (secure false, or express-session without cookie.secure); browsers also send it over plain HTTP
    severity: WARNING
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: '$RES.cookie($NAME, $VALUE, {..., secure: $SECURE, ...})'
              - pattern: '{..., cookie: {..., secure: $SECURE, ...}, ...}'
              - patterns:
                  - pattern: '$COOKIESESSION({..., secure: $SECURE, ...})'
                  - metavariable-regex:
                      metavariable: $COOKIESESSION
                      regex: (?i)^([\w$]+\.)*cookie_?session$
          - metavariable-pattern:
              metavariable: $SECURE
              pattern: 'false'
          - focus-metavariable: $SECURE
      - pattern: $SESSION.cookie.secure = false
      # express-session leaves secure off by default. Only inline options are
      # checked; options built elsewhere often set cookie.secure in production.
      - patterns:
          - pattern-either:
              - pattern-inside: |
                  $SESSION = require('express-session');
                  ...
              - pattern-inside: |
                  import $SESSION from 'express-session';
                  ...
          - pattern-either:
              - patterns:
                  - pattern: '$SESSION({...})'
                  - pattern-not: '$SESSION({..., cookie: $COOKIE, ...})'
              - patterns:
                  - pattern: '$SESSION({..., cookie: {...}, ...})'
                  - pattern-not: '$SESSION({..., cookie: {..., secure: $SECURE, ...}, ...})'
    metadata:
      cwe: CWE-614
      owasp: A05:2021

  - id: js-template-autoescape-disabled
    message: Template autoescaping disabled; values are rendered as raw HTML (cross-site scripting)
    severity: WARNING
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern: '{..., autoescape: $VALUE, ...}'
          - metavariable-pattern:
              metavariable: $VALUE
              pattern: 'false'
          - focus-metavariable: $VALUE
      - patterns:
          - pattern: '{..., noEscape: $VALUE, ...}'
          - metavariable-pattern:
              metavariable: $VALUE
              pattern: 'true'
          - focus-metavariable: $VALUE
    metadata:
      cwe: CWE-79
      owasp: A03:2021

  # JavaScript / TypeScript: Express and MongoDB
  - id: js-nosql-injection
    message: MongoDB query built from request data or a dynamic $where (possible NoSQL injection)
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern: '{..., $where: $CODE, ...}'
          - metavariable-pattern:
              metavariable: $CODE
              patterns:
                - pattern-not: '"..."'
                - pattern-not: 'function (...) { ... }'
          - focus-metavariable: $CODE
      - patterns:
          - pattern-either:
              - pattern: '$COLL.$METHOD({..., $KEY: req.$SOURCE.$FIELD, ...}, ...)'
              - pattern: '$COLL.$METHOD({..., $KEY: req.$SOURCE[$FIELD], ...}, ...)'
              - pattern: $COLL.$METHOD(req.$SOURCE, ...)
          - metavariable-regex:
              metavariable: $SOURCE
              regex: ^(body|query|cookies)$
          - metavariable-regex:
              metavariable: $METHOD
              regex: ^(find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|findOneAndRemove|findAndModify|update|updateOne|updateMany|remove|deleteOne|deleteMany|replaceOne|countDocuments|count|distinct)$
    metadata:
      cwe: CWE-943
      owasp: A03:2021

  - id: js-open-redirect
    message: Redirect target taken from the request (open redirect)
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - pattern: $RES.redirect($URL)
          - pattern: $RES.redirect($STATUS, $URL)
      - metavariable-pattern:
          metavariable: $URL
          patterns:
            - pattern: <... req.$SOURCE ...>
            - metavariable-regex:
                metavariable: $SOURCE
                regex: ^(query|params|body|param)$
      # A target that starts with a fixed string ('/users/' + id) cannot leave the site.
      - metavariable-regex:
          metavariable: $URL
          regex: ^(?!['"`][^'"`$])
    metadata:
      cwe: CWE-601
      owasp: A01:2021

  - id: js-hardcoded-session-secret
    message: Session or cookie signing secret is hard-coded; load it from the environment or a secret store
    severity: ERROR
    languages: [javascript, typescript]
    pattern-either:
      - patterns:
          - pattern-either:
              - pattern: '$SESSION({..., secret: $SECRET, ...})'
              - pattern: '$SESSION({..., keys: $SECRET, ...})'
          - metavariable-regex:
              metavariable: $SESSION
              regex: (?i)^([\w$]+\.)*[\w$]*session$
          - metavariable-pattern:
              metavariable: $SECRET
              pattern-either:
                - pattern: '"..."'
                - pattern: '[..., "...", ...]'
          - focus-metavariable: $SECRET
      - patterns:
          - pattern: $PARSER("...", ...)
          - metavariable-regex:
              metavariable: $PARSER
              regex: (?i)^([\w$]+\.)*cookie_?parser$
      - patterns:
          - pattern: '{..., $KEY: $SECRET, ...}'
          - metavariable-regex:
              metavariable: $KEY
              regex: (?i)^['"]?\w*(cookie|session)_?secret['"]?$
          - metavariable-pattern:
              metavariable: $SECRET
              pattern-either:
                - pattern: '"..."'
                - pattern: $ENV || "..."
          - focus-metavariable: $SECRET
    metadata:
      cwe: CWE-798
      owasp: A07:2021

  # JavaScript / TypeScript: request data reaching a dangerous call (taint mode, within one file)
  - id: js-sql-injection
    message: SQL query built from request data (SQL injection); pass values as query parameters
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources: &js-request
      - patterns:
          - pattern: $REQ.$ATTR
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
          - metavariable-regex:
              metavariable: $ATTR
              regex: ^(query|body|params|cookies|signedCookies|headers|files)$
      - patterns:
          - pattern-either:
              - pattern: $REQ.param(...)
              - pattern: $REQ.file.originalname
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
    pattern-sinks:
      - patterns:
          - pattern: $DB.$METHOD($QUERY, ...)
          - metavariable-regex:
              metavariable: $METHOD
              regex: ^\$?(query|execute|raw|queryRaw|queryRawUnsafe|executeRawUnsafe|unsafe)$
          # An options object (an ORM or GraphQL client) is not a query string.
          - pattern-not: $DB.$METHOD({...}, ...)
          - focus-metavariable: $QUERY
    pattern-sanitizers:
      - pattern-either:
          - pattern: parseInt(...)
          - pattern: parseFloat(...)
          - pattern: Number(...)
          - pattern: $X.escape(...)
      # A record looked up with request data (User.findById(req.params.id)) is stored data, not the request's.
      # Only the call's result: a callback passed to it still sees the request.
      - patterns:
          - pattern-either:
              - pattern: $STORE.get($KEY)
              - patterns:
                  - pattern: $STORE.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(find|findOne|findById|findByPk|findAll|findUnique|findFirst)$
          - pattern-not: $REQ.headers.get(...)
          - pattern-not: $URL.searchParams.get(...)
          # HTTP clients' get() sends a request; it doesn't look anything up.
          - pattern-not: axios.get(...)
          - pattern-not: got.get(...)
          - pattern-not: needle.get(...)
          - pattern-not: superagent.get(...)
          - pattern-not: request.get(...)
          - pattern-not: http.get(...)
          - pattern-not: https.get(...)
        exact: true
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: js-sql-formatted-query
    message: SQL query built by concatenation or a template literal; pass values as query parameters
    severity: WARNING
    languages: [javascript, typescript]
    patterns:
      - pattern-either:
          - patterns:
              - pattern: $DB.$METHOD("$SQL" + $X, ...)
              - metavariable-regex:
                  metavariable: $SQL
                  regex: (?is).*\b(select|insert|update|delete|replace)\b
              - pattern-not: $DB.$METHOD("..." + "...", ...)
          - patterns:
              - pattern: $DB.$METHOD($QUERY, ...)
              - metavariable-regex:
                  metavariable: $QUERY
                  regex: (?is)^`.*\b(select|insert|update|delete|replace)\b.*\$\{
      - metavariable-regex:
          metavariable: $METHOD
          regex: ^\$?(query|execute|raw|queryRaw|queryRawUnsafe|executeRawUnsafe|unsafe)$
      # Request data in the query is js-sql-injection's finding.
      - pattern-not: $DB.$METHOD(<... req.$ATTR ...>, ...)
      - pattern-not: $DB.$METHOD(<... request.$ATTR ...>, ...)
    metadata:
      cwe: CWE-89
      owasp: A03:2021

  - id: js-path-traversal
    message: File path built from request data (path traversal); use path.basename or a root directory that rejects ".."
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources: *js-request
    pattern-sinks:
      - patterns:
          - pattern-either:
              - patterns:
                  - pattern: $FS.$METHOD($PATH, ...)
                  - metavariable-regex:
                      metavariable: $FS
                      regex: ^(fs|fsp|fsPromises|fse|fs\.promises)$
                  - metavariable-regex:
                      metavariable: $METHOD
                      regex: ^(readFile|readFileSync|createReadStream|writeFile|writeFileSync|createWriteStream|appendFile|appendFileSync|unlink|unlinkSync|rm|rmSync|readdir|readdirSync|open|openSync)$
              - patterns:
                  - pattern-either:
                      - pattern: $RES.sendFile($PATH, ...)
                      - pattern: $RES.download($PATH, ...)
                  # With a root directory, Express rejects paths that leave it.
                  - pattern-not: '$RES.sendFile($PATH, {..., root: $ROOT, ...}, ...)'
                  - pattern-not: '$RES.download($PATH, {..., root: $ROOT, ...}, ...)'
          - focus-metavariable: $PATH
    pattern-sanitizers:
      - pattern-either:
          - pattern: path.basename(...)
          - pattern: parseInt(...)
          - pattern: Number(...)
      # A record looked up with request data (User.findById(req.params.id)) is stored data, not the request's.
      # Only the call's result: a callback passed to it still sees the request.
      - patterns:
          - pattern-either:
              - pattern: $STORE.get($KEY)
              - patterns:
                  - pattern: $STORE.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(find|findOne|findById|findByPk|findAll|findUnique|findFirst)$
          - pattern-not: $REQ.headers.get(...)
          - pattern-not: $URL.searchParams.get(...)
          # HTTP clients' get() sends a request; it doesn't look anything up.
          - pattern-not: axios.get(...)
          - pattern-not: got.get(...)
          - pattern-not: needle.get(...)
          - pattern-not: superagent.get(...)
          - pattern-not: request.get(...)
          - pattern-not: http.get(...)
          - pattern-not: https.get(...)
        exact: true
    metadata:
      cwe: CWE-22
      owasp: A01:2021

  - id: js-ssrf
    message: Outgoing request to a URL taken from request data (server-side request forgery)
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    pattern-sources: *js-request
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: fetch($URL, ...)
              - pattern: axios($URL, ...)
              - pattern: got($URL, ...)
              - pattern: request($URL, ...)
              - pattern: needle($M, $URL, ...)
              - pattern: needle.request($M, $URL, ...)
              - patterns:
                  - pattern: $CLIENT.$METHOD($URL, ...)
                  - metavariable-regex:
                      metavariable: $CLIENT
                      regex: ^(axios|got|needle|request|superagent|http|https)$
                  - metavariable-regex:
                      metavariable: $METHOD
                      regex: ^(get|post|put|patch|delete|head|options|request)$
                  - pattern-not: needle.request(...)
          - focus-metavariable: $URL
    pattern-sanitizers:
      # A URL that starts with a fixed scheme and host can't be pointed at another server.
      - patterns:
          - pattern: $URL
          - metavariable-regex:
              metavariable: $URL
              regex: ^['"`]https?://[^/'"`$]+/
      # A record looked up with request data (User.findById(req.params.id)) is stored data, not the request's.
      # Only the call's result: a callback passed to it still sees the request.
      - patterns:
          - pattern-either:
              - pattern: $STORE.get($KEY)
              - patterns:
                  - pattern: $STORE.$LOOKUP(...)
                  - metavariable-regex:
                      metavariable: $LOOKUP
                      regex: ^(find|findOne|findById|findByPk|findAll|findUnique|findFirst)$
          - pattern-not: $REQ.headers.get(...)
          - pattern-not: $URL.searchParams.get(...)
          # HTTP clients' get() sends a request; it doesn't look anything up.
          - pattern-not: axios.get(...)
          - pattern-not: got.get(...)
          - pattern-not: needle.get(...)
          - pattern-not: superagent.get(...)
          - pattern-not: request.get(...)
          - pattern-not: http.get(...)
          - pattern-not: https.get(...)
        exact: true
    metadata:
      cwe: CWE-918
      owasp: A10:2021

  - id: js-xss
    message: Request data written into an HTML response (cross-site scripting); escape it or render an autoescaped template
    severity: ERROR
    languages: [javascript, typescript]
    mode: taint
    # Only data copied, concatenated or formatted into the response: what a call returns
    # (a file's contents, an API response) is not the request data itself.
    options:
      taint_assume_safe_functions: true
      taint_assume_safe_indexes: true
    pattern-sources:
      - patterns:
          - pattern: $REQ.$ATTR
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
          - metavariable-regex:
              metavariable: $ATTR
              regex: ^(query|body|params|cookies|signedCookies|headers)$
      - patterns:
          - pattern: $REQ.param(...)
          - metavariable-regex:
              metavariable: $REQ
              regex: ^(req|request)$
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $RES.send($BODY)
              - pattern: $RES.write($BODY, ...)
              - pattern: $RES.end($BODY, ...)
          - metavariable-regex:
              metavariable: $RES
              regex: ^(res|response)(\.status\(.*\))?$
          # An object or array is sent as JSON, and so is a whole request object (req.query).
          - pattern-not: $RES.send({...})
          - pattern-not: $RES.send([...])
          - pattern-not: $RES.send(req.$ATTR)
          - pattern-not: $RES.send(request.$ATTR)
          - focus-metavariable: $BODY
    pattern-sanitizers:
      - pattern-either:
          - pattern: escape(...)
          - pattern: escapeHtml(...)
          - pattern: $LIB.escape(...)
          - pattern: he.encode(...)
          - pattern: xss(...)
          - pattern: DOMPurify.sanitize(...)
          - pattern: sanitizeHtml(...)
          - pattern: encodeURIComponent(...)
          - pattern: parseInt(...)
          - pattern: Number(...)
    metadata:
      cwe: CWE-79
      owasp: A03:2021

  - id: js-weak-password-hash
    message: Password or secret hashed with md5 or sha1; use a password hash (bcrypt, scrypt, argon2) or HMAC-SHA256
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern: $CRYPTO.createHash($ALG, ...).update($DATA, ...)
      - metavariable-regex:
          metavariable: $ALG
          regex: (?i)^['"`](rsa-)?(md5|sha1)['"`]$
      - metavariable-regex:
          metavariable: $DATA
          regex: (?is).*(passw|pwd|passphrase|secret)
    metadata:
      cwe: CWE-916
      owasp: A02:2021
"""
