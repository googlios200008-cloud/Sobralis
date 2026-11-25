#!/usr/bin/env bash
# Builds the offline prototype by default; the connected-test variant is synthetic-only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
: "${ANDROID_SDK_ROOT:?Set ANDROID_SDK_ROOT to an Android SDK containing platform 35 and build-tools 35.0.0}"
: "${JAVA_HOME:?Set JAVA_HOME to a JDK 17 installation}"
BT="$ANDROID_SDK_ROOT/build-tools/35.0.0"; [[ -x "$BT/aapt" ]] || BT="$ANDROID_SDK_ROOT/build-tools/android-15"
PLATFORM="$ANDROID_SDK_ROOT/platforms/android-35/android.jar"
for f in "$BT/aapt" "$BT/d8" "$BT/zipalign" "$BT/apksigner" "$PLATFORM" "$JAVA_HOME/bin/javac" "$JAVA_HOME/bin/keytool"; do [[ -e "$f" ]] || { echo "Missing $f" >&2; exit 1; }; done
export PATH="$JAVA_HOME/bin:$PATH"
export LANG=C.UTF-8 LC_ALL=C.UTF-8
PRIVATE=${SOBRALIS_ANDROID_PRIVATE_DIR:-"$HOME/sobralis-private-android"}; umask 077; mkdir -p "$PRIVATE"; chmod 700 "$PRIVATE"
KS="$PRIVATE/offline-test.keystore"; PASS="$PRIVATE/offline-test.pass"
if [[ ! -e "$KS" && ! -e "$PASS" ]]; then
  openssl rand -hex 32 > "$PASS"
  export SOBRALIS_KEY_PASSWORD; SOBRALIS_KEY_PASSWORD=$(cat "$PASS")
  "$JAVA_HOME/bin/keytool" -genkeypair -keystore "$KS" -storetype PKCS12 -storepass:env SOBRALIS_KEY_PASSWORD -keypass:env SOBRALIS_KEY_PASSWORD -alias offline-test -keyalg RSA -keysize 3072 -validity 10000 -dname 'CN=Sobralis offline test, O=Private development' >/dev/null
  unset SOBRALIS_KEY_PASSWORD
elif [[ ! -f "$KS" || ! -f "$PASS" ]]; then echo 'Signing key or password missing: refusing to replace it.' >&2; exit 1; fi
chmod 600 "$KS" "$PASS"
VARIANT=${SOBRALIS_ANDROID_VARIANT:-offline}
case "$VARIANT" in offline) ORIGIN= ;; connected-test) ORIGIN=${SOBRALIS_ANDROID_TEST_ORIGIN:?Set the synthetic HTTPS .test origin} ;; *) echo 'Unknown Android variant' >&2; exit 1 ;; esac
# Only .test hosts are allowed. This intentionally cannot be a production build.
python3 - "$ORIGIN" <<'PYVALIDATE'
import sys,re,urllib.parse
s=sys.argv[1]
if s:
 try:
  u=urllib.parse.urlsplit(s);host=u.hostname or '';port=u.port
  labels=host.split('.')
  ok=(u.scheme=='https' and u.netloc==host+((':'+str(port)) if port is not None else '') and len(host)<=253 and len(labels)>=2 and labels[-1]=='test' and all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) for x in labels) and (port is None or (1<=port<=65535 and port!=443)) and not u.path and not u.query and not u.fragment)
 except ValueError: ok=False
 if not ok: raise SystemExit('Connected test requires an exact synthetic HTTPS .test origin, with no path, credentials or query')
PYVALIDATE
W="$ROOT/android/build/$VARIANT"; rm -rf "$W"; mkdir -p "$W/assets/web/assets" "$W/classes" "$W/dex" "$W/generated/ru/sobralis/app"
python3 - "$ROOT/android/app/src/main/AndroidManifest.xml" "$W/AndroidManifest.xml" "$W/generated/ru/sobralis/app/OnlineConfig.java" "$ORIGIN" <<'PYCONFIG'
import sys,json,urllib.parse
src,out,java,origin=sys.argv[1:];s=open(src,encoding='utf8').read()
if origin:
 version='android:versionCode="1" android:versionName="0.1-offline"'
 if s.count(version)!=1 or s.count('  <uses-sdk')!=1 or 'android.permission.INTERNET' in s: raise SystemExit('Unexpected Android manifest; refusing connected test build')
 launcher='<intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>'
 activity='android:name=".MainActivity" android:exported="true"'
 if s.count(launcher)!=1 or s.count(activity)!=1:raise SystemExit('Unexpected activity manifest; refusing connected test build')
 u=urllib.parse.urlsplit(origin);port=(' android:port="'+str(u.port)+'"') if u.port is not None else ''
 deep='\n      <intent-filter android:autoVerify="false"><action android:name="android.intent.action.VIEW"/><category android:name="android.intent.category.DEFAULT"/><category android:name="android.intent.category.BROWSABLE"/><data android:scheme="https" android:host="'+u.hostname+'" android:path="/"'+port+'/></intent-filter>'
 s=s.replace(version,'android:versionCode="2" android:versionName="0.2-connected-test"').replace('  <uses-sdk','  <uses-permission android:name="android.permission.INTERNET" />\n  <uses-sdk').replace(activity,activity+' android:launchMode="singleTask"').replace(launcher,launcher+deep)
open(out,'w',encoding='utf8').write(s)
open(java,'w',encoding='utf8').write('package ru.sobralis.app; final class OnlineConfig { static final String ORIGIN = '+json.dumps(origin)+'; }\n')
PYCONFIG
for f in index.html style.css shared.css app.js enhancements.js party.js backup.js family.js shared.js trip-ui.js host-ui.js cloud.js manifest.webmanifest hero-web.webp hero.png; do cp "$ROOT/$f" "$W/assets/web/$f"; done
cp "$ROOT/assets/"{icon-192.png,icon-512.png,nunito-cyrillic.woff2,nunito-latin.woff2} "$W/assets/web/assets/"
cp "$ROOT/android/web/android.js" "$W/assets/web/android.js"
cp "$ROOT/android/web/online-init.js" "$W/assets/online-init.js"
python3 - "$W/assets/web/index.html" <<'PY'
import sys
p=sys.argv[1];s=open(p,encoding='utf8').read();needle='</body></html>'
if s.count(needle)!=1: raise SystemExit('Unexpected index.html ending')
open(p,'w',encoding='utf8').write(s.replace(needle,'<script src="android.js"></script>'+needle))
PY
"$BT/aapt" package -f -M "$W/AndroidManifest.xml" -S "$ROOT/android/app/src/main/res" -A "$W/assets" -I "$PLATFORM" -F "$W/unsigned.apk"
"$JAVA_HOME/bin/javac" -encoding UTF-8 --release 8 -classpath "$PLATFORM" -d "$W/classes" "$ROOT/android/app/src/main/java/ru/sobralis/app/MainActivity.java" "$ROOT/android/app/src/main/java/ru/sobralis/app/OnlinePolicy.java" "$W/generated/ru/sobralis/app/OnlineConfig.java"
find "$W/classes" -name '*.class' -print0 | xargs -0 "$BT/d8" --lib "$PLATFORM" --min-api 23 --output "$W/dex"
(cd "$W/dex" && "$BT/aapt" add "$W/unsigned.apk" classes.dex >/dev/null)
"$BT/zipalign" -f 4 "$W/unsigned.apk" "$W/aligned.apk"
OUT=${1:-"$ROOT/artifacts/sobralis-$VARIANT-test.apk"}; mkdir -p "$(dirname "$OUT")"
"$BT/apksigner" sign --ks "$KS" --ks-key-alias offline-test --ks-pass "file:$PASS" --out "$OUT" "$W/aligned.apk"
"$BT/apksigner" verify --verbose "$OUT"
"$BT/aapt" dump badging "$OUT" | head -8
printf '\n%s test APK: %s\n' "$VARIANT" "$OUT"
