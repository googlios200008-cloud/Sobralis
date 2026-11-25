#!/usr/bin/env python3
"""Static package checks only: no claim about running Android."""
import hashlib, pathlib, sys, zipfile
root = pathlib.Path(__file__).resolve().parent.parent
apk = pathlib.Path(sys.argv[1])
assets = ['style.css','shared.css','app.js','enhancements.js','party.js','backup.js','family.js','shared.js','trip-ui.js','host-ui.js','cloud.js','manifest.webmanifest','hero-web.webp','hero.png','assets/icon-192.png','assets/icon-512.png','assets/nunito-cyrillic.woff2','assets/nunito-latin.woff2']
with zipfile.ZipFile(apk) as z:
    for p in assets:
        assert z.read('assets/web/'+p)==(root/p).read_bytes(), p
    assert z.read('assets/web/android.js') == (root/'android/web/android.js').read_bytes()
    html=z.read('assets/web/index.html').decode('utf8')
    assert html == (root/'index.html').read_text().replace('</body></html>','<script src="android.js"></script></body></html>')
    assert 'classes.dex' in z.namelist()
print('APK assets match tracked sources; SHA-256',hashlib.sha256(apk.read_bytes()).hexdigest())
