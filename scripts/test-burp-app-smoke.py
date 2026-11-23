#!/usr/bin/env python3
"""Subprocess tests for the optional/required Burp application smoke gate."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

binary = str(Path(sys.argv[1]).resolve())
name = 'scan_library::tests::builtins_load_from_the_local_burp_install'
keys = ('WEBPROBE_BURP_JAR', 'WEBPROBE_BURP_APP_JAR', 'WEBPROBE_BURP_BUILTINS', 'WEBPROBE_REQUIRE_BURP_APP')

def run(values, ok, marker):
    env = dict(os.environ)
    for key in keys:
        env.pop(key, None)
    env.update(values)
    result = subprocess.run([binary, '--exact', name, '--nocapture'], env=env, capture_output=True, text=True, timeout=30)
    output = result.stdout + result.stderr
    assert ('running 1 test' in output), output
    assert (result.returncode == 0) == ok, output
    assert marker in output, output

with tempfile.TemporaryDirectory(prefix='burp-app-smoke-') as tmp:
    tmp = Path(tmp)
    api = tmp / 'arbitrary-api-name.zip'
    with zipfile.ZipFile(api, 'w') as jar:
        jar.writestr('burp/api/montoya/MontoyaApi.class', b'fixture')
    app = tmp / 'arbitrary-application-name.zip'
    with zipfile.ZipFile(app, 'w') as jar:
        for i in range(29):
            label = 'Audit checks - passive' if i == 0 else f'Config {i}'
            jar.writestr(f'resources/BuiltInConfigs/{label}.json', '{}')
        jar.writestr('resources/Preferences/CrawlDefaults.json', json.dumps({'crawler': {'crawl_limits': {'maximum_crawl_time': 60}}}))
    run({'WEBPROBE_BURP_JAR': str(api)}, True, 'BURP_APP_SMOKE_NOT_RUN')
    run({'WEBPROBE_BURP_APP_JAR': str(app), 'WEBPROBE_REQUIRE_BURP_APP': '1'}, True, 'BURP_APP_SMOKE_EXECUTED')
    for bad in (api, tmp / 'missing.jar'):
        run({'WEBPROBE_BURP_APP_JAR': str(bad)}, False, 'WEBPROBE_BURP_APP_JAR')
    run({'WEBPROBE_REQUIRE_BURP_APP': '1'}, False, 'WEBPROBE_REQUIRE_BURP_APP requires')
print('5 subprocess smoke-gate scenarios passed; synthetic fixtures only')
