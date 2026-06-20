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

    // 4a2. okhttp3.CertificatePinner — lazy-loaded, not present at startup
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
    //     verify() opens a live HTTPS connection, computes SHA-256 of the
    //     server cert, then compares against hardcoded hash:
    //     "da61debb8deda1425393f4b8c1191f78b4b37c1edca5ef532a2c7c2d1a676c30"
    //     We bypass by simply returning true without doing any of that.
    safeHook('HostNameVerifierSSL.verify()', function () {
        HNVSSL.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function (hostname, session) {
                console.log('[*] HostNameVerifierSSL.verify(' + hostname + ') → true (pin bypassed)');
                return true;
            };
    });

    // Also hook mc1.o000ooO0() — the final string-equality check that compares
    // the computed hex digest against the hardcoded pin hash.
    // If verify() hook is bypassed for any reason, this kills the comparison itself.
    safeHook('mc1.o000ooO0() — cert pin hash comparison', function () {
        mc1.o000ooO0.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                var args = Array.prototype.slice.call(arguments);
                // args[1] is the hardcoded pin hash — detect and short-circuit
                if (args.some(function (a) {
                    return typeof a === 'string' && a.length === 64 &&
                           /^[0-9a-f]+$/.test(a);  // looks like a SHA-256 hex string
                })) {
                    console.log('[*] mc1.o000ooO0() cert hash comparison → true');
                    return true;
                }
                return ovl.apply(this, arguments);
            };
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

    // 4p. Sanitise any remaining SSL exception messages before they reach the UI.
    //     Catches anything that slips through the upstream hooks.
    safeHook('SSLException message sanitiser', function () {
        var SSLEx = Java.use('javax.net.ssl.SSLException');
        SSLEx.$init.overload('java.lang.String').implementation = function (msg) {
            console.log('[!] SSLException sanitised: ' + msg);
            this.$init('Connection error');
        };
        SSLEx.$init.overload('java.lang.String', 'java.lang.Throwable').implementation = function (msg, cause) {
            console.log('[!] SSLException(cause) sanitised: ' + msg);
            this.$init('Connection error', cause);
        };
    });

    console.log('\n[✓] MASTER BYPASS ACTIVE\n' +
                '    Root detection : all gates bypassed\n' +
                '    SSL pinning    : com.android.okhttp + conscrypt + NSC bypassed\n');

    // ════════════════════════════════════════════════════════════════
    // SECTION 5 — INLINE RECON: find shaded CertificatePinner at runtime
    // for check() method — that is the shaded okhttp3.CertificatePinner
    // ════════════════════════════════════════════════════════════════
    setTimeout(function () {
        console.log('\n[SCAN] Searching for shaded CertificatePinner...');
        var pinnerFound = [];

        Java.perform(function () {
            Java.enumerateLoadedClasses({
                onMatch: function (cls) {
                    try {
                        var C = Java.use(cls);
                        C.class.getDeclaredMethods().forEach(function (m) {
                            var mname = m.getName();
                            if (mname === 'check' || mname === 'checkPins') {
                                console.log('[PINNER-FOUND] ' + cls + '.' + mname + '()');
                                pinnerFound.push({ cls: cls, method: mname });
                            }
                        });
                    } catch (_) {}
                },
                onComplete: function () {
                    console.log('[SCAN] Done. Found ' + pinnerFound.length + ' check() candidates.');

                    pinnerFound.forEach(function (item) {
                        try {
                            var C = Java.use(item.cls);
                            C[item.method].overloads.forEach(function (ovl) {
                                ovl.implementation = function () {
                                    console.log('[BYPASS] ' + item.cls + '.' + item.method + '() → no-op');
                                };
                            });
                            console.log('[+] Hooked: ' + item.cls + '.' + item.method + '()');
                        } catch (e) {
                            console.log('[-] Hook failed ' + item.cls + ': ' + e);
                        }
                    });

                    // Also heap-scan for any constructed CertificatePinner instances
                    pinnerFound.forEach(function (item) {
                        try {
                            Java.choose(item.cls, {
                                onMatch: function (obj) {
                                    try {
                                        obj[item.method].overloads.forEach(function (ovl) {
                                            ovl.implementation = function () {
                                                console.log('[BYPASS-HEAP] ' + item.cls + '.' + item.method + '() → no-op');
                                            };
                                        });
                                        console.log('[+] Heap-patched: ' + item.cls);
                                    } catch (_) {}
                                },
                                onComplete: function () {}
                            });
                        } catch (_) {}
                    });

                    console.log('[✓] Scan complete — tap login now');
                }
            });

            // Hook ALL exception constructors to catch pinning failure message
            ['java.io.IOException',
             'javax.net.ssl.SSLException',
             'java.lang.RuntimeException',
             'java.lang.IllegalStateException'
            ].forEach(function (cls) {
                try {
                    var Ex = Java.use(cls);
                    Ex.$init.overload('java.lang.String').implementation = function (msg) {
                        if (msg && msg.indexOf('pinning') !== -1) {
                            console.log('[PIN-EX] Suppressed: ' + msg.substring(0, 150));
                            this.$init('OK');
                            return;
                        }
                        this.$init(msg);
                    };
                } catch (_) {}
            });
        });
    }, 4000);
});