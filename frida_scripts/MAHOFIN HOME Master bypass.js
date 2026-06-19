'use strict';
Java.perform(function () {
    function safeHook(tag, fn) {
        try { fn(); console.log('[+] ' + tag); }
        catch (e) { console.log('[-] ' + tag + ': ' + e); }
    }
    safeHook('SecurityUtils.isEmulator()', function () {
        var SU = Java.use('com.Macom.emicollection.app.common.SecurityUtils');
        SU.isEmulator.implementation = function () {
            console.log('[*] SecurityUtils.isEmulator() → false');
            return false;
        };
    });
    safeHook('SecurityUtils.hasEmulatorFiles()', function () {
        var SU = Java.use('com.Macom.emicollection.app.common.SecurityUtils');
        SU.hasEmulatorFiles.implementation = function () {
            console.log('[*] SecurityUtils.hasEmulatorFiles() → false');
            return false;
        };
    });
    safeHook('MainActivity.showSecurityErrorAndExit()', function () {
        var MA = Java.use('com.Macom.emicollection.MainActivity');
        MA.showSecurityErrorAndExit.implementation = function (title, msg) {
            console.log('[!] showSecurityErrorAndExit() suppressed: ' + title);
        };
    });
    safeHook('MainActivity.dispatchTouchEvent()', function () {
        var MA  = Java.use('com.Macom.emicollection.MainActivity');
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
    safeHook('LoginFragment.isFridaDetected()', function () {
        var LF = Java.use('com.Macom.emicollection.content.login.presentation.LoginFragment');
        LF.isFridaDetected.implementation = function () {
            console.log('[*] isFridaDetected() → false');
            return false;
        };
    });
    safeHook('LoginFragment sub-checks', function () {
        var LF = Java.use('com.Macom.emicollection.content.login.presentation.LoginFragment');
        LF.detectFridaFiles.implementation       = function () { return false; };
        LF.detectFridaProcess.implementation     = function () { return false; };
        LF.detectFridaPort.implementation        = function () { return false; };
        LF.detectFridaThreads.implementation     = function () { return false; };
        LF.checkFridaEnvironment.implementation  = function () { return false; };
        LF.isEmulator.implementation             = function () { return false; };
        LF.isDebuggerAttached.implementation     = function () { return false; };
    });
    safeHook('LoginFragment dialog suppressors', function () {
        var LF = Java.use('com.Macom.emicollection.content.login.presentation.LoginFragment');
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
        var RB = Java.use('com.Macom.emicollection.o31');
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
        Java.use('com.Macom.emicollection.qc1')
            .class.getDeclaredMethods()
            .forEach(function (m) {
                var name = m.getName();
                try {
                    Java.use('com.Macom.emicollection.qc1')[name]
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
    safeHook('a4.OooO00o() — shaded CertificatePinner CONFIRMED', function () {
        var a4 = Java.use('com.Macom.emicollection.a4');
        a4.OooO00o.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] a4.OooO00o() → no-op (cert pin check bypassed)');
            };
        });
    });
    safeHook('okhttp3.CertificatePinner direct', function () {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] okhttp3.CertificatePinner.check() → bypassed');
            };
        });
        try {
            CP['check$okhttp'].overloads.forEach(function (ovl) {
                ovl.implementation = function () {
                    console.log('[*] okhttp3.CertificatePinner.check$okhttp() → bypassed');
                };
            });
        } catch (_) {}
    });
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
    safeHook('NetworkSecurityTrustManager', function () {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overloads.forEach(function (ovl) {
            ovl.implementation = function () {
                console.log('[*] NetworkSecurityTrustManager.checkServerTrusted() → bypassed');
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
    safeHook('HostNameVerifierSSL.verify() concrete', function () {
        var HNVSSL = Java.use('com.Macom.emicollection.app.common.HostNameVerifierSSL');
        HNVSSL.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
            .implementation = function (hostname, session) {
                console.log('[*] HostNameVerifierSSL.verify(' + hostname + ') → true');
                return true;
            };
    });
    safeHook('mc1.o000ooO0() — cert pin hash comparison', function () {
        var mc1 = Java.use('com.Macom.emicollection.mc1');
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
    safeHook('URL.openConnection() — block HostNameVerifierSSL inner request', function () {
        var URL = Java.use('java.net.URL');
        URL.openConnection.overload().implementation = function () {
            var urlStr = this.toString();
            console.log('[*] URL.openConnection(): ' + urlStr);
            var conn = this.openConnection();
            return conn;
        };
    });
    safeHook('MessageDigest.digest() — return expected pin bytes', function () {
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
    safeHook('HostNameVerifierSSL heap scan', function () {
        Java.choose('com.Macom.emicollection.app.common.HostNameVerifierSSL', {
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
                if (!hooked[cls] && cls.indexOf('com.Macom.emicollection') !== -1) {
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
    safeHook('Throwable pinning failure interceptor', function () {
        var Throwable = Java.use('java.lang.Throwable');
        var hooked = {};  // track which classes we already hooked
        Throwable.$init.overload('java.lang.String').implementation = function (msg) {
            if (msg && msg.indexOf('Certificate pinning failure') !== -1) {
                console.log('[!!!] PIN FAILURE THROW SITE:');
                var trace = this.getStackTrace();
                for (var i = 0; i < Math.min(trace.length, 20); i++) {
                    var cls  = trace[i].getClassName();
                    var meth = trace[i].getMethodName();
                    console.log('  [' + i + '] ' + cls + '.' + meth);
                    if (!hooked[cls] && cls.indexOf('com.Macom.emicollection') !== -1) {
                        try {
                            var C = Java.use(cls);
                            C.check.overloads.forEach(function (ovl) {
                                ovl.implementation = function () {
                                    console.log('[BYPASS] ' + cls + '.check() → no-op (dynamic)');
                                };
                            });
                            hooked[cls] = true;
                            console.log('[+] Dynamically hooked: ' + cls + '.check()');
                        } catch (_) {
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
                this.$init('');
                return;
            }
            this.$init(msg);
        };
    });
});