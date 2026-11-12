"""The command-line package (pyproject.toml): its metadata, its contents and the files around it.

These tests only read files, so they run wherever `make test` does. Building the wheel and running
the installed `sast-triage` command is `make package-check` (tests/package_check.py).
"""
import ast
import re
import tomllib
from pathlib import Path

import scan_repo

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = 'https://github.com/lansiquo/sast-triage'
# Never part of the command-line package: the GitHub App, durable mode, and everything that is not code it runs.
NOT_PACKAGED = {'app', 'worker', 'job_store', 'job_payload', 'manage_jobs', 'queue_maintenance',
                'deploy', 'tests', 'rules', 'docs'}


def pyproject():
    return tomllib.loads((ROOT / 'pyproject.toml').read_text(encoding='utf-8'))


def requirements(name):
    """The requirement lines of a requirements file, without comments and blank lines."""
    lines = (line.strip() for line in (ROOT / name).read_text(encoding='utf-8').splitlines())
    return [line for line in lines if line and not line.startswith('#')]


def own_imports(path):
    """Top-level names of this repository's modules and packages that the file imports, at any depth."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            names.update(alias.name.split('.')[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split('.')[0])
    return {name for name in names
            if (ROOT / f'{name}.py').is_file() or any((ROOT / name).glob('*.py'))}


def command_line_modules():
    """Every module and package of this repository that scan_repo.py imports, directly or through another."""
    found, pending = set(), ['scan_repo']
    while pending:
        name = pending.pop()
        if name in found:
            continue
        found.add(name)
        module = ROOT / f'{name}.py'
        for path in [module] if module.is_file() else sorted((ROOT / name).rglob('*.py')):
            pending.extend(own_imports(path))
    return found


def test_metadata_names_the_package_its_license_author_and_supported_pythons():
    project = pyproject()['project']
    assert project['name'] == 'sast-triage'
    assert project['requires-python'] == '>=3.11'
    assert project['description'].strip()
    assert project['readme'] == 'README.md'
    assert project['license'] == 'MIT'
    assert project['license-files'] == ['LICENSE']
    assert (ROOT / 'LICENSE').read_text(encoding='utf-8').startswith('MIT License')
    assert project['authors'] and all(author.get('name') for author in project['authors'])
    assert project['urls'], 'project URLs are missing'
    assert all(url == REPOSITORY or url.startswith(REPOSITORY + '/') for url in project['urls'].values())


def test_version_is_static_and_not_older_than_the_newest_release():
    """No version automation: the number is written in pyproject.toml, and a release sets the final one there."""
    project = pyproject()['project']
    assert 'dynamic' not in project, 'every field is static, the version included'
    version = re.fullmatch(r'(\d+)\.(\d+)\.(\d+)(\.dev\d+)?', project['version'])
    assert version, f"{project['version']} is not X.Y.Z or a development release X.Y.Z.devN"
    released = re.search(r'^## \[(\d+)\.(\d+)\.(\d+)\]', (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8'), re.M)
    package = (tuple(map(int, version.groups()[:3])), version[4] is None)   # X.Y.Z.devN comes before X.Y.Z
    assert package >= (tuple(map(int, released.groups())), True), (
        f"pyproject.toml version {project['version']} is older than {released[0][3:]}, the newest release in "
        'CHANGELOG.md: a release sets its number in pyproject.toml')


def test_dependencies_are_exactly_those_of_requirements_cli():
    project = pyproject()['project']
    assert project['dependencies'] == requirements('requirements-cli.txt')
    assert 'optional-dependencies' not in project


def test_build_system_is_setuptools_and_nothing_else():
    build = pyproject()['build-system']
    assert build['build-backend'] == 'setuptools.build_meta'
    assert 'backend-path' not in build
    # The requirement's name ends at the first character that cannot be part of one.
    assert [re.split(r'[^A-Za-z0-9._-]', requirement, maxsplit=1)[0].lower()
            for requirement in build['requires']] == ['setuptools']


def test_console_script_sast_triage_points_at_scan_repo_main():
    project = pyproject()['project']
    assert project['scripts'] == {'sast-triage': 'scan_repo:main'}
    assert 'gui-scripts' not in project and 'entry-points' not in project
    assert callable(scan_repo.main)


def test_package_holds_exactly_what_the_command_line_imports():
    """Nothing scan_repo.py needs is left out, and the App, the worker, deploy/ and the tests stay out."""
    setuptools = pyproject()['tool']['setuptools']
    assert setuptools['include-package-data'] is False
    for module in setuptools['py-modules']:
        assert (ROOT / f'{module}.py').is_file(), module
    for package in setuptools['packages']:
        assert any((ROOT / package).glob('*.py')), package
    packaged = set(setuptools['py-modules']) | set(setuptools['packages'])
    assert packaged == command_line_modules()
    assert not packaged & NOT_PACKAGED


def test_gitignore_covers_the_build_output():
    ignored = (ROOT / '.gitignore').read_text(encoding='utf-8').splitlines()
    for pattern in ('/build/', '/dist/', '/*.egg-info/'):
        assert pattern in ignored, f'.gitignore needs {pattern}'


def test_makefile_adds_package_check_and_leaves_check_as_it_was():
    makefile = (ROOT / 'Makefile').read_text(encoding='utf-8')
    assert '\ncheck: test selfcheck\n' in makefile, '`make check` is still the suite, then the selfcheck'
    assert re.search(r'^package-check:\n\t.*tests/package_check\.py$', makefile, re.M)
    assert 'package-check' in re.search(r'^\.PHONY:(.*)$', makefile, re.M)[1].split()
    assert (ROOT / 'tests' / 'package_check.py').is_file()


def test_readme_shows_the_offline_build_and_says_the_package_is_not_on_pypi():
    readme = (ROOT / 'README.md').read_text(encoding='utf-8')
    assert readme.count('\n## Install as a package (local build)\n') == 1
    section = readme.split('\n## Install as a package (local build)\n')[1].split('\n## ')[0]
    assert 'python -m pip wheel --no-deps --no-build-isolation --no-index -w ' in section
    assert 'pip install --no-index ' in section
    assert 'sast-triage /path/to/project' in section
    assert 'not published to PyPI' in section
    assert 'make package-check' in section
