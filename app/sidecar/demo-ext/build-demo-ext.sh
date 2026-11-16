#!/bin/sh
# Build demo-ext.jar: a real Montoya extension for verifying the sidecar bridge.
# Usage: sh build-demo-ext.sh   (requires javac/jar and /opt/BurpSuite/burpsuite.jar)
set -e
cd "$(dirname "$0")"
mkdir -p build/META-INF/services
printf 'DemoExtension\n' > build/META-INF/services/burp.api.montoya.BurpExtension
javac -sourcepath empty-src -cp /opt/BurpSuite/burpsuite.jar -d build DemoExtension.java
jar cf demo-ext.jar -C build .
echo "built $(pwd)/demo-ext.jar"
