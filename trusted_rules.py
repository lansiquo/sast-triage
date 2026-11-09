"""Service-owned rules for Python, JavaScript and TypeScript, shared with the credential-free local showcase."""
OFFLINE_RULESET = r"""
rules:
  # Crypto: weak hashes
  - id: py-weak-md5
    message: Use of weak hash (md5)
    severity: ERROR
    languages: [python]
    pattern: hashlib.md5(...)
    metadata:
      cwe: CWE-327
      owasp: A02:2021

  - id: py-weak-sha1
    message: Use of weak hash (sha1)
    severity: ERROR
    languages: [python]
    pattern: hashlib.sha1(...)
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
    severity: ERROR
    languages: [javascript, typescript]
    patterns:
      - pattern: $CRYPTO.createHash($ALG, ...)
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
"""
