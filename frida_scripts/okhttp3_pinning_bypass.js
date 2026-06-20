'use strict';
// Find the shaded okhttp3 CertificatePinner by scanning for its unique string
// "Certificate pinning failure!" is hardcoded in exactly one class
Java.perform(function () {

    setTimeout(function () {
        var found = [];

        Java.enumerateLoadedClasses({
            onMatch: function (cls) {
                try {
                    var C = Java.use(cls);
                    var methods = C.class.getDeclaredMethods();
                    var fields  = C.class.getDeclaredFields();

                    methods.forEach(function (m) {
                        var mname = m.getName();
                        if (mname === 'check' || mname === 'checkPins') {
                            console.log('[CHECK] ' + cls + '.' + mname);
                            found.push(cls);
                        }
                    });

                    // Look for String fields that could hold pin hashes (length ~50 chars base64)
                    fields.forEach(function (f) {
                        var fname = f.getName();
                        var ftype = f.getType().getName();
                        if (ftype === 'java.lang.String' || ftype === 'java.util.Set' ||
                            ftype === '[Ljava.lang.String;') {
                            try {
                                f.setAccessible(true);
                                // Just log field name — value needs instance
                                console.log('[FIELD] ' + cls + '.' + fname + ' : ' + ftype);
                            } catch(_) {}
                        }
                    });
                } catch (_) {}
            },
            onComplete: function () {
                console.log('[SCAN] Complete. Classes with check(): ' + found.join(', '));

                // Now hook all found classes
                found.forEach(function (cls) {
                    try {
                        var C = Java.use(cls);
                        C.check.overloads.forEach(function (ovl) {
                            ovl.implementation = function () {
                                console.log('[BYPASS] ' + cls + '.check() → no-op');
                            };
                        });
                        console.log('[+] Hooked: ' + cls + '.check()');
                    } catch (e) {
                        console.log('[-] Hook failed ' + cls + ': ' + e);
                    }
                });

                console.log('[✓] All check() methods hooked — tap login now');
            }
        });
    }, 4000); // Wait 4s for app to fully initialize

    // Also hook ALL exception constructors to catch the pin failure message
    ['java.io.IOException',
     'javax.net.ssl.SSLException',
     'java.lang.RuntimeException',
     'java.lang.IllegalStateException'
    ].forEach(function (cls) {
        try {
            var Ex = Java.use(cls);
            Ex.$init.overload('java.lang.String').implementation = function (msg) {
                if (msg && msg.indexOf('pinning') !== -1) {
                    console.log('[PIN-EXCEPTION] ' + cls + ': ' + msg.substring(0, 200));
                }
                this.$init(msg);
            };
        } catch(_) {}
    });

    // Hook com.android.okhttp.OkHttpClient.newCall to log URLs
    try {
        var OHC = Java.use('com.android.okhttp.OkHttpClient');
        OHC.newCall.implementation = function (req) {
            try { console.log('[URL] ' + req.url().toString()); } catch(_) {}
            return this.newCall(req);
        };
    } catch(_) {}

    console.log('[✓] recon3 active — waiting 4s then scanning...');
});