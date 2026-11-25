#!/usr/bin/env python3
"""Static package/validation checks only; not an Android or TLS device test."""
import os, pathlib, re, subprocess, zipfile
root=pathlib.Path(__file__).resolve().parent.parent
sdk=pathlib.Path(os.environ['ANDROID_SDK_ROOT'])
bt=sdk/'build-tools'/'35.0.0'
if not (bt/'aapt').exists():bt=sdk/'build-tools'/'android-15'
off=root/'android/build/android-offline-isolated.apk';connected=root/'android/build/android-connected-isolated.apk'
def call(*args):return subprocess.run(args,check=True,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE).stdout
def details(apk):return call(str(bt/'aapt'),'dump','badging',str(apk)),call(str(bt/'aapt'),'dump','xmltree',str(apk),'AndroidManifest.xml')
ob,om=details(off);cb,cm=details(connected)
assert "name='ru.sobralis.app' versionCode='1'" in ob and 'android.permission.INTERNET' not in ob
assert "name='ru.sobralis.app' versionCode='2'" in cb and "uses-permission: name='android.permission.INTERNET'" in cb
assert 'android.intent.action.VIEW' not in om and 'android.intent.category.BROWSABLE' not in om
assert len(re.findall(r'A: android:name[^\n]*="android.intent.action.VIEW"',cm))==1
assert len(re.findall(r'A: android:name[^\n]*="android.intent.category.BROWSABLE"',cm))==1
assert re.search(r'android:autoVerify[^\n]*0x0',cm) and re.search(r'android:launchMode[^\n]*0x2',cm)
for attribute,value in (('scheme','https'),('host','sobralis.example.test'),('path','/')):
 assert re.search(r'android:'+attribute+r'[^\n]*="'+re.escape(value)+r'"',cm),attribute
assert 'android:port' not in cm
port_apk=root/'android/build/android-connected-port-check.apk'
if port_apk.exists():
 _,port_manifest=details(port_apk)
 assert re.search(r'android:port[^\n]*="8443"',port_manifest)
for m in (om,cm):
 assert re.search(r'android:allowBackup.*0x0',m) and re.search(r'android:usesCleartextTraffic.*0x0',m)
for apk in (off,connected):
 call(str(bt/'zipalign'),'-c','4',str(apk))
 with zipfile.ZipFile(apk) as z:assert z.read('assets/online-init.js')==(root/'android/web/online-init.js').read_bytes()
def cert(apk):
 s=call(str(bt/'apksigner'),'verify','--print-certs',str(apk));return re.search(r'certificate SHA-256 digest: ([0-9a-f]+)',s).group(1)
assert cert(off)==cert(connected)
if os.environ.get('SOBRALIS_REFERENCE_APK'):assert cert(off)==cert(pathlib.Path(os.environ['SOBRALIS_REFERENCE_APK']))
script=str(root/'scripts/build-android-offline.sh')
for origin in ['http://example.test','https://example.com','https://example.test/','https://user@example.test','https://example.test?x=1','https://a.test.evil.com','https://127.0.0.1','https://example.test:65536','https://example.test:443']:
 env=os.environ.copy();env.update(SOBRALIS_ANDROID_VARIANT='connected-test',SOBRALIS_ANDROID_TEST_ORIGIN=origin)
 p=subprocess.run([script,str(root/'android/build/invalid.apk')],cwd=root,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 assert p.returncode!=0,origin
print('Android variants: scoped permission, versions, same certificate, assets and invalid origins passed')
