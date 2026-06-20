'use strict';

// ====================================================================
// Single script — root detection + SSL pinning combined
//
// GATE 1 — MainActivity.onCreate()
//   SecurityUtils.isEmulator() / hasEmulatorFiles()
//   showSecurityErrorAndExit() suppressed
//   dispatchTouchEvent() bypassed
//
// GATE 2 — LoginFragment
//   isFridaDetected() + all 5 sub-checks
//   isEmulator() / isDebuggerAttached()
//   All show*Dialog() suppressed
//
// LOW-LEVEL FALLBACKS
//   File.exists()         → hides frida + root paths
//   System.getenv()       → nulls FRIDA_HOME
//   Thread.getName()      → spoofs frida/gum-js-loop names
//   BufferedReader        → strips Frida port from /proc/net/tcp
//   qc1 string helper     → blocks frida keyword searches
//   Debug.isDebuggerConnected() → false
//   Build fields          → spoofed to Samsung Galaxy S10
//   FLAG_SECURE           → stripped
//
//   com.android.okhttp.CertificatePinner          → check() no-op
//   com.android.org.conscrypt.TrustManagerImpl    → verifyChain() bypassed
//   android.security.net.config.NetworkSecurityTrustManager → bypassed
//   android.security.net.config.RootTrustManager  → bypassed
//   com.android.okhttp.internal.tls.OkHostnameVerifier → verify() → true
//   com.android.org.conscrypt.OkHostnameVerifier  → verify() → true
//   com.android.org.conscrypt.ConscryptHostnameVerifier → verify() → true
//   SSLContext.init()     → permissive TrustManager injected
//   X509TrustManager heap scan
//   X509ExtendedTrustManager heap scan
//   HostnameVerifier heap scan
//   SSLPeerUnverifiedException → suppressed
// ====================================================================

Java.perform(function () {

    function safeHook(tag, fn) {
        try { fn(); console.log('[+] ' + tag); }
        catch (e) { console.log('[-] ' + tag + ': ' + e); }
    }

    // ════════════════════════════════════════════════════════════════
    // SECTION 1 — GATE 1: MainActivity
    // ════════════════════════════════════════════════════════════════

    safeHook('SecurityUtils.isEmulator()', function () {
        SU.isEmulator.implementation = function () {
            console.log('[*] SecurityUtils.isEmulator() → false');
            return false;
        };
    });

    safeHook('SecurityUtils.hasEmulatorFiles()', function () {
        SU.hasEmulatorFiles.implementation = function () {
            console.log('[*] SecurityUtils.hasEmulatorFiles() → false');
            return false;
        };
    });

    safeHook('MainActivity.showSecurityErrorAndExit()', function () {
        MA.showSecurityErrorAndExit.implementation = function (title, msg) {
            console.log('[!] showSecurityErrorAndExit() suppressed: ' + title);
        };
    });

    safeHook('MainActivity.dispatchTouchEvent()', function () {
        var ACA = Java.use('androidx.appcompat.app.AppCompatActivity');
        MA.dispatchTouchEvent
            .overload('android.view.MotionEvent')
            .implementation = function (ev) {
                return ACA.dispatchTouchEvent.call(this, ev);
            };
    });

    safeHook('FLAG_SECURE strip', function () {
        var Window = Java.use('android.view.Window');
        Window.setFlags.implementation = function (flags, mask) {
            this.setFlags(flags & ~0x2000, mask & ~0x2000);
        };
        try { Window.setHideOverlayWindows.implementation = function () {}; } catch (_) {}
    });

    // ════════════════════════════════════════════════════════════════
    // SECTION 2 — GATE 2: LoginFragment
    // ════════════════════════════════════════════════════════════════

    safeHook('LoginFragment.isFridaDetected()', function () {
        LF.isFridaDetected.implementation = function () {
            console.log('[*] isFridaDetected() → false');
            return false;
        };
    });

    safeHook('LoginFragment sub-checks', function () {
        LF.detectFridaFiles.implementation       = function () { return false; };
        LF.detectFridaProcess.implementation     = function () { return false; };
        LF.detectFridaPort.implementation        = function () { return false; };
        LF.detectFridaThreads.implementation     = function () { return false; };
        LF.checkFridaEnvironment.implementation  = function () { return false; };
        LF.isEmulator.implementation             = function () { return false; };
        LF.isDebuggerAttached.implementation     = function () { return false; };
    });

    safeHook('LoginFragment dialog suppressors', function () {
        LF.showFridaDetectionDialog.implementation = function () {
            console.log('[!] showFridaDetectionDialog() suppressed');
        };
        LF.showEmulatorDialog.implementation = function () {
            console.log('[!] showEmulatorDialog() suppressed');
        };
        LF.showRootAccessDialog.implementation = function () {
            console.log('[!] showRootAccessDialog() suppressed');
        };
        LF.showSecurityDialog.implementation = function (msg) {
            console.log('[!] showSecurityDialog() suppressed: ' + msg);
        };
    });

    safeHook('RootBeer o31', function () {
        RB.class.getDeclaredMethods().forEach(function (m) {
            if (m.getReturnType().getName() === 'boolean') {
                var name = m.getName();
                try {
                    RB[name].overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            console.log('[*] o31.' + name + '() → false');
                            return false;
                        };
                    });
                } catch (_) {}
            }
        });
    });

    // ════════════════════════════════════════════════════════════════
    // SECTION 3 — LOW-LEVEL FALLBACKS
    // ════════════════════════════════════════════════════════════════

    safeHook('Debug.isDebuggerConnected()', function () {
        Java.use('android.os.Debug')
            .isDebuggerConnected.implementation = function () { return false; };
    });

    safeHook('File.exists()', function () {
        var BLOCKED = [
            '/data/local/tmp/frida-server',
            '/data/local/tmp/re.frida.server',
            '/data/local/tmp/frida',
            '/system/xbin/su', '/system/bin/su', '/sbin/su',
            '/data/local/xbin/su', '/data/local/bin/su',
            '/system/app/Superuser.apk',
            '/magisk', '/sbin/magisk', '/data/adb/magisk',
            '/system/xbin/busybox', '/system/bin/busybox',
        ];
        var File = Java.use('java.io.File');
        File.exists.implementation = function () {
            var path = this.getAbsolutePath();
            if (BLOCKED.some(function (p) { return path === p || path.indexOf(p) !== -1; })) {
                console.log('[*] File.exists() → false: ' + path);
                return false;
            }
            return this.exists();
        };
    });

    safeHook('System.getenv()', function () {
        Java.use('java.lang.System')
            .getenv.overload('java.lang.String')
            .implementation = function (key) {
                if (key && key.toLowerCase().indexOf('frida') !== -1) {
                    console.log('[*] System.getenv(' + key + ') → null');
                    return null;
                }
                return this.getenv(key);
            };
    });

    safeHook('Thread.getName() spoof', function () {
        Java.use('java.lang.Thread').getName.implementation = function () {
            var name = this.getName();
            if (name && (
                name.toLowerCase().indexOf('frida') !== -1 ||
                name.indexOf('gum-js-loop') !== -1 ||
                name.indexOf('gmain') !== -1
            )) {
                return 'pool-thread-' + Math.floor(Math.random() * 100);
            }
            return name;
        };
    });

    safeHook('BufferedReader.readLine() — Frida port filter', function () {
        Java.use('java.io.BufferedReader')
            .readLine.overload()
            .implementation = function () {
                var line = this.readLine();
                if (line !== null && line.indexOf('5D8A') !== -1) {
                    console.log('[*] BufferedReader: Frida port entry stripped');
                    return '';
                }
                return line;
            };
    });

    safeHook('qc1 string helper', function () {
        var FRIDA_NEEDLES = ['frida', 'gum-js-loop', ':5D8A', '5D8A', 'gmain', 'FRIDA'];
            .class.getDeclaredMethods()
            .forEach(function (m) {
                var name = m.getName();
                try {
                        .overloads.forEach(function (ovl) {
                            ovl.implementation = function () {
                                var args = Array.prototype.slice.call(arguments);
                                var isFridaSearch = args.some(function (a) {
                                    return typeof a === 'string' &&
                                        FRIDA_NEEDLES.some(function (n) {
                                            return a.indexOf(n) !== -1;
                                        });
                                });
                                if (isFridaSearch) {
                                    console.log('[*] qc1.' + name + '() Frida search → false');
                                    return false;
                                }
                                return ovl.apply(this, arguments);
                            };
                        });
                } catch (_) {}
            });
    });

    safeHook('Build fields spoof', function () {
        var B = Java.use('android.os.Build');
        B.BRAND.value        = 'samsung';
        B.DEVICE.value       = 'beyond1';
        B.HARDWARE.value     = 'exynos9820';
        B.MODEL.value        = 'SM-G973F';
        B.MANUFACTURER.value = 'samsung';
        B.PRODUCT.value      = 'beyond1';
        B.FINGERPRINT.value  =
            'samsung/beyond1/beyond1:11/RP1A.200720.012/G973FXXU4EUA6:user/release-keys';
        B.TAGS.value         = 'release-keys';
        B.TYPE.value         = 'user';
    });

    // ════════════════════════════════════════════════════════════════
    // SECTION 4 — SSL PINNING BYPASS
    // All classes confirmed present via Java.enumerateLoadedClassesSync()
    // ════════════════════════════════════════════════════════════════

    // 4a. com.android.okhttp.CertificatePinner
    //     THE primary cert pinner in this app — check() throws when pins mismatch
    safeHook('com.android.okhttp.CertificatePinner.check()', function () {
        var CP = Java.use('com.android.okhttp.CertificatePinner');

        CP.check.overload('java.lang.String', 'java.util.List')
            .implementation = function (hostname, certs) {
                console.log('[*] CertificatePinner.check(' + hostname + ') → bypassed');
            };

        try {
            CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
                .implementation = function (hostname, certs) {
                    console.log('[*] CertificatePinner.check[](' + hostname + ') → bypassed');
                };
        } catch (_) {}

        try {
            CP.check.overload('java.lang.String')
                .implementation = function (hostname) {
                    console.log('[*] CertificatePinner.check(' + hostname + ') → bypassed');
                };
        } catch (_) {}
    });

    //      Stack trace confirmed: a4.OooO00o:16 is the EXACT throw site
    //      of "Certificate pinning failure!" with sha256/ format.
    //      This is the shaded okhttp3.CertificatePinner renamed to a4.
    safeHook('a4.OooO00o() — shaded CertificatePinner CONFIRMED', function () {

        // From stack trace: a4.OooO00o:16 is the ONLY method that throws
        // "Certificate pinning failure!" — hook ONLY this method, nothing else.
        // Hooking other methods (OooO0O0, equals, hashCode) crashes the app
        // because they are needed by the OkHttp interceptor chain.
        a4.OooO00o.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] a4.OooO00o() → no-op (cert pin check bypassed)');
                // This is check() — it returns void, just don't throw
            };
        });
    });

    // ga is the OkHttp interceptor — DO NOT hook it, intercept() must return Response

    // 4a3. okhttp3.CertificatePinner — lazy-loaded, not present at startup

    //      It loads lazily when the first HTTP call is made.
    //      Strategy: hook ClassLoader to intercept it the moment it loads,
    //      AND try direct hook (works if it loads before Java.perform completes).

    // Direct hook attempt (works if already loaded by login time)
    safeHook('okhttp3.CertificatePinner direct', function () {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] okhttp3.CertificatePinner.check() → bypassed');
            };
        });
        // Also hook check$okhttp on newer okhttp3 versions
        try {
            CP['check$okhttp'].overloads.forEach(function (ovl) {
                ovl.implementation = function () {
                    console.log('[*] okhttp3.CertificatePinner.check$okhttp() → bypassed');
                };
            });
        } catch (_) {}
    });

    // ClassLoader hook — fires the instant okhttp3.CertificatePinner is loaded
    safeHook('ClassLoader hook for okhttp3.CertificatePinner', function () {
        var ClassLoader = Java.use('java.lang.ClassLoader');
        ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
            var clazz = this.loadClass(name);
            if (name === 'okhttp3.CertificatePinner') {
                console.log('[*] ClassLoader: okhttp3.CertificatePinner loaded — patching now');
                try {
                    var CP = Java.use('okhttp3.CertificatePinner');
                    CP.check.overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            console.log('[*] okhttp3.CertificatePinner.check() → bypassed (lazy)');
                        };
                    });
                } catch (e) {
                    console.log('[-] lazy CertificatePinner hook: ' + e);
                }
            }
            return clazz;
        };
    });

    // SSLException message hook — "Certificate pinning failure!" originates here.
    // The exception is constructed in CertificatePinner.check() with this exact string.
    // By intercepting the IOException that wraps it, we prevent it reaching Retrofit.
    safeHook('SSLPinningException via IOException constructor', function () {
        var IOException = Java.use('java.io.IOException');
        IOException.$init.overload('java.lang.String').implementation = function (msg) {
            if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                console.log('[!] CertificatePinner IOException suppressed');
                this.$init('OK');
                return;
            }
            this.$init(msg);
        };

        // Also catch it as a plain RuntimeException (okhttp3 wraps differently per version)
        var RuntimeException = Java.use('java.lang.RuntimeException');
        RuntimeException.$init.overload('java.lang.String').implementation = function (msg) {
            if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                console.log('[!] CertificatePinner RuntimeException suppressed');
                this.$init('OK');
                return;
            }
            this.$init(msg);
        };
    });

    // 4b. com.android.org.conscrypt.TrustManagerImpl
    //     Handles X.509 chain validation — source of CERTIFICATE_VERIFY_FAILED
    safeHook('conscrypt.TrustManagerImpl.verifyChain()', function () {
        Java.use('com.android.org.conscrypt.TrustManagerImpl')
            .verifyChain.implementation = function (
                untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData
            ) {
                console.log('[*] TrustManagerImpl.verifyChain(' + host + ') → bypassed');
                return untrustedChain;
            };
    });

    safeHook('conscrypt.TrustManagerImpl checkTrusted methods', function () {
        var TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TMI.class.getDeclaredMethods().forEach(function (m) {
            var mname = m.getName();
            if (mname.indexOf('checkTrusted') !== -1 || mname.indexOf('Trusted') !== -1) {
                try {
                    TMI[mname].overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            console.log('[*] TrustManagerImpl.' + mname + '() → bypassed');
                            var retType = m.getReturnType().getName();
                            if (retType === 'void') return;
                            if (retType.indexOf('List') !== -1) return arguments[0];
                            return null;
                        };
                    });
                } catch (_) {}
            }
        });
    });

    // 4c. android.security.net.config.NetworkSecurityTrustManager
    //     Android 7+ — enforces pins from network_security_config.xml
    safeHook('NetworkSecurityTrustManager', function () {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');

        NSTM.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] NetworkSecurityTrustManager.checkServerTrusted() → bypassed');
                // Some overloads return List<X509Certificate> — must return empty list not void
                var retType = ovl.returnType ? ovl.returnType.className : 'void';
                if (retType !== 'void') {
                    return Java.use('java.util.ArrayList').$new();
                }
            };
        });

        try {
            NSTM.checkPins.overloads.forEach(function (ovl) {
                ovl.implementation = function () {
                    console.log('[*] NetworkSecurityTrustManager.checkPins() → bypassed');
                };
            });
        } catch (_) {}
    });

    // 4d. android.security.net.config.RootTrustManager
    //     HAS a List-returning overload: checkServerTrusted(chain, authType, host) → List
    //     Returning void from it causes: "expected return value compatible with java.util.List"
    safeHook('RootTrustManager', function () {
        var RTM = Java.use('android.security.net.config.RootTrustManager');
        RTM.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] RootTrustManager.checkServerTrusted() → bypassed');
                var retType = ovl.returnType ? ovl.returnType.className : 'void';
                if (retType !== 'void') {
                    return Java.use('java.util.ArrayList').$new();
                }
            };
        });
    });

    // 4e. com.android.okhttp.internal.tls.OkHostnameVerifier
    safeHook('com.android.okhttp.OkHostnameVerifier', function () {
        var HV = Java.use('com.android.okhttp.internal.tls.OkHostnameVerifier');
        HV.verify.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                var host = arguments[0] || '?';
                console.log('[*] android.okhttp.OkHostnameVerifier.verify(' + host + ') → true');
                var retType = ovl.returnType ? ovl.returnType.className : 'boolean';
                if (retType !== 'void') return true;
            };
        });
    });

    // 4f. com.android.org.conscrypt.OkHostnameVerifier
    safeHook('conscrypt.OkHostnameVerifier', function () {
        var HV = Java.use('com.android.org.conscrypt.OkHostnameVerifier');
        HV.verify.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                var host = arguments[0] || '?';
                console.log('[*] conscrypt.OkHostnameVerifier.verify(' + host + ') → true');
                var retType = ovl.returnType ? ovl.returnType.className : 'boolean';
                if (retType !== 'void') return true;
            };
        });
    });

    // 4g. com.android.org.conscrypt.ConscryptHostnameVerifier
    safeHook('conscrypt.ConscryptHostnameVerifier', function () {
        var HV = Java.use('com.android.org.conscrypt.ConscryptHostnameVerifier');
        HV.verify.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                var host = arguments[0] || '?';
                console.log('[*] ConscryptHostnameVerifier.verify(' + host + ') → true');
                var retType = ovl.returnType ? ovl.returnType.className : 'boolean';
                if (retType !== 'void') return true;
            };
        });
    });

    // 4h. SSLContext.init() — inject permissive TrustManager into every new SSL context
    safeHook('SSLContext.init() — permissive TrustManager', function () {
        var X509TM = Java.use('javax.net.ssl.X509TrustManager');
        var PermTM = Java.registerClass({
            name: 'com.frida.bypass.PermissiveTrustManager',
            implements: [X509TM],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {
                    console.log('[*] PermissiveTM.checkServerTrusted() → no-op');
                },
                getAcceptedIssuers: function () {
                    return Java.array('java.security.cert.X509Certificate', []);
                }
            }
        });

        var tmArray = Java.array('javax.net.ssl.TrustManager', [PermTM.$new()]);

        Java.use('javax.net.ssl.SSLContext')
            .init.overload(
                '[Ljavax.net.ssl.KeyManager;',
                '[Ljavax.net.ssl.TrustManager;',
                'java.security.SecureRandom'
            ).implementation = function (km, tm, sr) {
                console.log('[*] SSLContext.init() → permissive TM injected');
                this.init(km, tmArray, sr);
            };
    });

    // 4i. Heap scan — X509ExtendedTrustManager instances already constructed
    safeHook('X509ExtendedTrustManager heap scan', function () {
        Java.choose('javax.net.ssl.X509ExtendedTrustManager', {
            onMatch: function (tm) {
                try {
                    tm.checkServerTrusted.overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            console.log('[*] X509ExtendedTM[heap].checkServerTrusted() → no-op');
                        };
                    });
                } catch (_) {}
            },
            onComplete: function () { console.log('[*] X509ExtendedTrustManager heap done'); }
        });
    });

    // 4j. Heap scan — X509TrustManager instances already constructed
    safeHook('X509TrustManager heap scan', function () {
        Java.choose('javax.net.ssl.X509TrustManager', {
            onMatch: function (tm) {
                try {
                    tm.checkServerTrusted.overloads.forEach(function (ovl) {
                        ovl.implementation = function () {
                            console.log('[*] X509TrustManager[heap].checkServerTrusted() → no-op');
                        };
                    });
                } catch (_) {}
            },
            onComplete: function () { console.log('[*] X509TrustManager heap done'); }
        });
    });

    // 4k. Heap scan — HostnameVerifier instances already constructed
    safeHook('HostnameVerifier heap scan', function () {
        Java.choose('javax.net.ssl.HostnameVerifier', {
            onMatch: function (hv) {
                try {
                    hv.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
                        .implementation = function (host) {
                            console.log('[*] HostnameVerifier[heap].verify(' + host + ') → true');
                            return true;
                        };
                } catch (_) {}
            },
            onComplete: function () { console.log('[*] HostnameVerifier heap done'); }
        });
    });

    // 4l. HttpsURLConnection — suppress any default verifier/factory overrides
    safeHook('HttpsURLConnection defaults', function () {
        var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
        HUC.setDefaultHostnameVerifier.implementation = function (hv) {
            console.log('[*] HttpsURLConnection.setDefaultHostnameVerifier() suppressed');
        };
        try {
            HUC.setDefaultSSLSocketFactory.implementation = function (sf) {
                console.log('[*] HttpsURLConnection.setDefaultSSLSocketFactory() suppressed');
            };
        } catch (_) {}
    });

    safeHook('com.android.okhttp.HttpsURLConnectionImpl', function () {
        var IMPL = Java.use('com.android.okhttp.internal.huc.HttpsURLConnectionImpl');
        try {
            IMPL.setHostnameVerifier.implementation = function (hv) {
                console.log('[*] HttpsURLConnectionImpl.setHostnameVerifier() suppressed');
            };
        } catch (_) {}
    });

    // 4m. HostNameVerifierSSL — CUSTOM CERT PINNER (source verified)
    //
    //     APPROACH 1: Hook concrete class directly
    safeHook('HostNameVerifierSSL.verify() concrete', function () {
        HNVSSL.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function (hostname, session) {
                console.log('[*] HostNameVerifierSSL.verify(' + hostname + ') → true');
                return true;
            };
    });

    //     APPROACH 2: Hook mc1.o000ooO0() — the ONLY place the hash is compared.
    //     This is the deepest possible hook — even if verify() is called through
    //     reflection or interface dispatch, the comparison itself returns true.
    safeHook('mc1.o000ooO0() — cert pin hash comparison', function () {
        mc1.o000ooO0.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                if (args.some(function (a) {
                    return typeof a === 'string' && a.length === 64 &&
                           /^[0-9a-f]+$/.test(a);
                })) {
                    console.log('[*] mc1.o000ooO0() cert hash → true');
                    return true;
                }
                return ovl.apply(this, arguments);
            };
        });
    });

    //     APPROACH 3: Hook URL.openConnection() — HostNameVerifierSSL.verify()
    //     calls new URL("https://", hostname).openConnection() to make its OWN
    //     fresh HTTPS connection for cert pinning.
    //     If we make openConnection() return a connection that skip the handshake,
    //     getServerCertificates() never runs and the whole check is bypassed.
    safeHook('URL.openConnection() — block HostNameVerifierSSL inner request', function () {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            var urlStr = this.toString();
            console.log('[*] URL.openConnection(): ' + urlStr);
            var conn = this.openConnection();
            return conn;
        };
    });

    //     APPROACH 4: Hook MessageDigest.digest() — the SHA-256 computation
    //     inside verify(). Replace the digest bytes with the bytes of the
    //     expected hash so the comparison always succeeds.
    safeHook('MessageDigest.digest() — return expected pin bytes', function () {
        // Expected hex: da61debb8deda1425393f4b8c1191f78b4b37c1edca5ef532a2c7c2d1a676c30
        var expectedHex = 'da61debb8deda1425393f4b8c1191f78b4b37c1edca5ef532a2c7c2d1a676c30';
        var expectedBytes = [];
        for (var i = 0; i < expectedHex.length; i += 2) {
            expectedBytes.push(parseInt(expectedHex.substr(i, 2), 16));
        }
        var javaBytes = Java.array('byte', expectedBytes.map(function(b) {
            return b > 127 ? b - 256 : b;
        }));

        var MD = Java.use('java.security.MessageDigest');
        MD.digest.overload().implementation = function () {
            var alg = this.getAlgorithm();
            if (alg === 'SHA-256') {
                console.log('[*] MessageDigest.digest(SHA-256) → returning expected pin bytes');
                return javaBytes;
            }
            return this.digest();
        };
    });

    //     APPROACH 5: Heap scan — find the actual HostNameVerifierSSL instance
    //     and patch it directly on the object
    safeHook('HostNameVerifierSSL heap scan', function () {
            onMatch: function (obj) {
                console.log('[*] HostNameVerifierSSL instance found on heap — patching');
                obj.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
                    .implementation = function (hostname, session) {
                        console.log('[*] HostNameVerifierSSL[heap].verify(' + hostname + ') → true');
                        return true;
                    };
            },
            onComplete: function () { console.log('[*] HostNameVerifierSSL heap scan done'); }
        });
    });

    // 4n. REMOVED — SSLPeerUnverifiedException $init hook caused "message = bypassed"
    //     to appear in the app's login error dialog because the app catches exceptions
    //     and forwards their .getMessage() directly to the UI error handler.
    //     All SSL throw sites are blocked upstream; this hook is not needed.

    // 4o. HttpsURLConnection.getServerCertificates() — called inside HostNameVerifierSSL
    //     If the inner connection fails, swallow the exception silently.
    safeHook('getServerCertificates() guard', function () {
        var HUC = Java.use('javax.net.ssl.HttpsURLConnection');
        try {
            HUC.getServerCertificates.implementation = function () {
                try {
                    return this.getServerCertificates();
                } catch (e) {
                    console.log('[!] getServerCertificates() swallowed: ' + e.message);
                    return Java.array('java.security.cert.Certificate', []);
                }
            };
        } catch (_) {}
    });

    // 4p. SSLException interceptor — prints full stack trace to find the
    //     exact shaded CertificatePinner class, then dynamically hooks it.
    safeHook('SSLException stack trace interceptor', function () {
        var SSLEx = Java.use('javax.net.ssl.SSLException');
        var hooked = {};

        function handlePinException(msg, twoArg, cause) {
            console.log('\n[!!!] SSLException PIN FAILURE — stack trace:');
            var probe = Java.use('java.lang.Exception').$new();
            var trace = probe.getStackTrace();
            for (var i = 0; i < Math.min(trace.length, 25); i++) {
                var cls  = trace[i].getClassName();
                var meth = trace[i].getMethodName();
                var line = trace[i].getLineNumber();
                console.log('  [' + i + '] ' + cls + '.' + meth + ':' + line);

                    try {
                        var C = Java.use(cls);
                        C.check.overloads.forEach(function (ovl) {
                            ovl.implementation = function () {
                                console.log('[DYNAMIC-BYPASS] ' + cls + '.check() → no-op');
                            };
                        });
                        hooked[cls] = true;
                        console.log('[+] DYNAMICALLY HOOKED: ' + cls + '.check()');
                    } catch (_) {}
                }
            }
        }

        SSLEx.$init.overload('java.lang.String')
            .implementation = function (msg) {
                if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                    handlePinException(msg, false, null);
                    this.$init('');
                    return;
                }
                this.$init(msg);
            };

        SSLEx.$init.overload('java.lang.String', 'java.lang.Throwable')
            .implementation = function (msg, cause) {
                if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                    handlePinException(msg, true, cause);
                    this.$init('', cause);
                    return;
                }
                this.$init(msg, cause);
            };
    });

    console.log('\n[✓] MASTER BYPASS ACTIVE\n' +
                '    Root detection : all gates bypassed\n' +
                '    SSL pinning    : com.android.okhttp + conscrypt + NSC bypassed\n');

    // ════════════════════════════════════════════════════════════════
    // SECTION 5 — FIND + HOOK shaded CertificatePinner via stack trace
    // Throwable.$init catches the exact throw site and reveals class name
    // then immediately hooks it so subsequent calls are bypassed
    // ════════════════════════════════════════════════════════════════
    safeHook('Throwable pinning failure interceptor', function () {
        var Throwable = Java.use('java.lang.Throwable');
        var hooked = {};  // track which classes we already hooked

        Throwable.$init.overload('java.lang.String').implementation = function (msg) {
            if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                console.log('[!!!] PIN FAILURE THROW SITE:');

                // Print stack to find the pinner class
                var trace = this.getStackTrace();
                for (var i = 0; i < Math.min(trace.length, 20); i++) {
                    var cls  = trace[i].getClassName();
                    var meth = trace[i].getMethodName();
                    console.log('  [' + i + '] ' + cls + '.' + meth);

                        try {
                            var C = Java.use(cls);
                            // Try hooking check() on this class
                            C.check.overloads.forEach(function (ovl) {
                                ovl.implementation = function () {
                                    console.log('[BYPASS] ' + cls + '.check() → no-op (dynamic)');
                                };
                            });
                            hooked[cls] = true;
                            console.log('[+] Dynamically hooked: ' + cls + '.check()');
                        } catch (_) {
                            // Not the pinner, try other methods
                            try {
                                var C2 = Java.use(cls);
                                C2[meth].overloads.forEach(function (ovl) {
                                    ovl.implementation = function () {
                                        console.log('[BYPASS] ' + cls + '.' + meth + '() → no-op');
                                        var rt = ovl.returnType ? ovl.returnType.className : 'void';
                                        if (rt !== 'void') return null;
                                    };
                                });
                                hooked[cls] = true;
                            } catch (_2) {}
                        }
                    }
                }

                // Swallow the exception — replace with empty message
                // so app's error handler gets nothing meaningful
                this.$init('');
                return;
            }
            this.$init(msg);
        };
    });

});