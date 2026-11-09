"""Real scanner compatibility checks; fixture source is scanned, never executed."""
import os
os.environ['PRSEC_LOAD_DOTENV'] = '0'
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import OFFLINE_RULESET
from analyzers.semgrep_runner import run_semgrep

SOURCE = '''import hashlib, os, pickle, random, subprocess, tarfile, tempfile, yaml
hashlib.md5(b"sample")  # nosemgrep
hashlib.sha1(b"sample")
yaml.load("example")
yaml.unsafe_load("example")
pickle.loads(b"example")
pickle.load(stream)
os.system(user_input)
os.popen(user_input)
subprocess.run(user_input, shell=True)
eval(user_input)
exec(user_input)
requests.get("https://example.invalid", verify=False)
random.random()
tempfile.mktemp()
with tarfile.open("example.tar") as archive:
    archive.extractall("target")
'''
EXPECTED = {'py-weak-md5','py-weak-sha1','py-unsafe-yaml-load','py-unsafe-yaml-unsafe-load',
    'py-insecure-deserialization-pickle-loads','py-insecure-deserialization-pickle-load',
    'py-os-system','py-os-popen','py-subprocess-shell-true','py-dangerous-eval','py-dangerous-exec',
    'py-requests-disable-verify','py-random-for-secrets','py-tempfile-mktemp','py-tarfile-extractall'}
JS_SOURCE = '''const cp = require("child_process");
const vm = require("vm");
const crypto = require("crypto");
const session = require("express-session");
const serialize = require("node-serialize");
eval(req.body.code);  // nosemgrep
new Function("a", body);
vm.runInNewContext(req.body.code, {});
cp.exec("ls " + dir);
serialize.unserialize(req.cookies.profile);
crypto.createHash("md5");
const resetToken = Math.random().toString(36);
https.request({ host, rejectUnauthorized: false });
res.cookie("sid", id, { httpOnly: false });
app.use(session({ secret: "keyboard cat" }));
swig.setDefaults({ autoescape: false });
users.findOne({ userName: req.body.userName });
res.redirect(req.query.url);
'''
JS_EXPECTED = {'js-dangerous-eval','js-implied-eval','js-vm-dynamic-code','js-child-process-exec',
    'js-insecure-deserialization-node-serialize','js-weak-hash','js-math-random-for-secrets',
    'js-tls-verification-disabled','js-cookie-without-httponly','js-cookie-without-secure',
    'js-template-autoescape-disabled','js-nosql-injection','js-open-redirect','js-hardcoded-session-secret'}


def main():
    with tempfile.TemporaryDirectory(prefix='prsec_compatibility_') as temporary:
        root=Path(temporary)
        (root/'all_rules.py').write_text(SOURCE)
        (root/'all_rules.js').write_text(JS_SOURCE)
        (root/'clean.py').write_text('import hashlib\nhashlib.sha256(b"sample")\n')
        (root/'clean.js').write_text('const crypto = require("crypto");\ncrypto.createHash("sha256");\n')
        rules=root/'trusted.yml';rules.write_text(OFFLINE_RULESET)
        findings=run_semgrep(['all_rules.py','all_rules.js'],str(root),config=str(rules))
        actual={f['rule_id'] for f in findings}
        expected=EXPECTED|JS_EXPECTED
        assert actual == expected, f'Unexpected rule coverage: missing={expected-actual}, extra={actual-expected}'
        assert not run_semgrep(['clean.py','clean.js'],str(root),config=str(rules))
        print(f'PASS: all {len(expected)} trusted rules; inline nosemgrep cannot suppress MD5 or eval; clean comparison passes.')


if __name__ == '__main__': main()
