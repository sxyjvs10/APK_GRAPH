"use strict";
Java.perform(function() {
    console.log('\n[*] ChitsqPay bypass v2 starting...\n');
    try {
        Java.use("android.view.Window")
            .setFlags.overload("int", "int")
            .implementation = function(f, m) {
                this.setFlags(f & ~8192, m & ~8192);
            };
        console.log('[+] FLAG_SECURE stripped');
    } catch(e) { console.log('[-] FLAG_SECURE: ' + e.message); }
    try {
        var MainActivity = Java.use('com.macom.chitsqpaynew.activities.MainActivity');
        MainActivity.getAppSignature.implementation = function() {
            console.log('[+] getAppSignature() → bypassed, calling rootCheck()');
            this.rootCheck();
        };
        console.log('[+] getAppSignature() hooked');
    } catch(e) { console.log('[-] getAppSignature: ' + e.message); }
    try {
        var RootUtil = Java.use('com.macom.chitsqpaynew.utilities.RootUtil');
        RootUtil.isDeviceRooted.implementation = function() {
            console.log('[+] RootUtil.isDeviceRooted() → false');
            return false;
        };
        console.log('[+] RootUtil.isDeviceRooted() hooked');
    } catch(e) { console.log('[-] RootUtil: ' + e.message); }
    try {
        var Activity = Java.use('android.app.Activity');
        Activity.finish.overload().implementation = function() {
            var name = this.getClass().getName();
            if (name.indexOf('macom') !== -1 || name.indexOf('chitsq') !== -1) {
                console.log('[!] finish() blocked in: ' + name);
                return;
            }
            this.finish();
        };
        console.log('[+] Activity.finish() guarded');
    } catch(e) { console.log('[-] Activity.finish: ' + e.message); }
    try {
        var MessageDigest = Java.use('java.security.MessageDigest');
        MessageDigest.digest.overload('[B').implementation = function(input) {
            var result = this.digest(input);
            var algo = this.getAlgorithm();
            if (algo === 'SHA' || algo === 'SHA-1') {
                try {
                    var Base64 = Java.use('android.util.Base64');
                    var expected = Base64.decode(
                        'HzaZB5XtyrdGVyC5Sxwk2NgD46M==',  // padded
                        2  // Base64.NO_WRAP
                    );
                    console.log('[+] MessageDigest.digest(SHA) → returning expected signature hash');
                    return expected;
                } catch(_) {}
            }
            return result;
        };
        console.log('[+] MessageDigest.digest() hooked');
    } catch(e) { console.log('[-] MessageDigest: ' + e.message); }
    var okhttp3Hooked = false;
    try {
        var CP = Java.use('okhttp3.CertificatePinner');
        CP.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(host, certs) {
                console.log('[+] OkHttp3 SSL pin bypassed: ' + host);
            };
        okhttp3Hooked = true;
        console.log('[+] okhttp3.CertificatePinner.check(String,List) hooked');
    } catch(e) {}
    try {
        var CP2 = Java.use('okhttp3.CertificatePinner');
        CP2['check$okhttp'].implementation = function(host, lazyCerts) {
            console.log('[+] OkHttp3 check$okhttp bypassed: ' + host);
        };
        okhttp3Hooked = true;
        console.log('[+] okhttp3.CertificatePinner.check$okhttp hooked');
    } catch(e) {}
    if (!okhttp3Hooked) console.log('[-] okhttp3 CertificatePinner not found');
    try {
        Java.use('com.android.org.conscrypt.TrustManagerImpl')
            .verifyChain.implementation = function(u, t, h, c, o, s) { return u; };
        console.log('[+] conscrypt.TrustManagerImpl.verifyChain() hooked');
    } catch(e) {}
    try {
        var T = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        T.checkTrusted.overloads.forEach(function(ov) {
            ov.implementation = function() { return null; };
        });
        ['checkServerTrusted','checkClientTrusted'].forEach(function(m) {
            try {
                T[m].overloads.forEach(function(ov) { ov.implementation = function() {}; });
            } catch(_) {}
        });
        console.log('[+] conscrypt checkTrusted hooked');
    } catch(e) { console.log('[-] conscrypt checkTrusted: ' + e.message); }
    try {
        var NSTM = Java.use('android.security.net.config.NetworkSecurityTrustManager');
        NSTM.checkServerTrusted.overloads.forEach(function(ov) {
            ov.implementation = function() {};
        });
        try { NSTM.checkPins.implementation = function() {}; } catch(_) {}
        console.log('[+] NetworkSecurityTrustManager hooked');
    } catch(e) { console.log('[-] NSTM: ' + e.message); }
    try {
        Java.use('android.security.net.config.RootTrustManager')
            .checkServerTrusted.overloads
            .forEach(function(ov) { ov.implementation = function() {}; });
        console.log('[+] RootTrustManager hooked');
    } catch(e) { console.log('[-] RootTrustManager: ' + e.message); }
    try {
        Java.use('javax.net.ssl.SSLContext').init
            .overload('[Ljavax.net.ssl.KeyManager;','[Ljavax.net.ssl.TrustManager;','java.security.SecureRandom')
            .implementation = function(km, tm, sr) {
                try { this.init(km, null, sr); }
                catch(_) { try { this.init(km, tm, sr); } catch(__) {} }
            };
        console.log('[+] SSLContext.init() hooked');
    } catch(e) {}
    try {
        var H = Java.use('javax.net.ssl.HttpsURLConnection');
        H.setDefaultHostnameVerifier.implementation = function() {};
        H.setDefaultSSLSocketFactory.implementation = function() {};
        console.log('[+] HttpsURLConnection defaults overridden');
    } catch(e) {}
    setTimeout(function() {
        try {
            Java.choose('javax.net.ssl.X509TrustManager', {
                onMatch: function(obj) {
                    try {
                        obj.checkServerTrusted.overloads.forEach(function(ov) {
                            ov.implementation = function() {};
                        });
                    } catch(_) {}
                },
                onComplete: function() {}
            });
            console.log('[+] X509TrustManager heap scan done');
        } catch(_) {}
    }, 2000);
    try {
        Java.use('com.android.okhttp.CertificatePinner')
            .check.overloads.forEach(function(ov) { ov.implementation = function() {}; });
        console.log('[+] com.android.okhttp.CertificatePinner hooked');
    } catch(e) {}
    try {
        var TMDelegate = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLContextBuilder$TrustManagerDelegate');
        TMDelegate.checkServerTrusted.implementation = function(chain, authType) {
            console.log('[+] msebera TrustManagerDelegate.checkServerTrusted() bypassed');
        };
        console.log('[+] cz.msebera TrustManagerDelegate hooked');
    } catch(e) { console.log('[-] msebera TrustManagerDelegate: ' + e.message); }
    try {
        var SSLContextBuilder = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLContextBuilder');
        SSLContextBuilder.build.implementation = function() {
            console.log('[+] msebera SSLContextBuilder.build() — injecting trust-all');
            var ctx = this.build();
            return ctx;
        };
        console.log('[+] cz.msebera SSLContextBuilder.build() hooked');
    } catch(e) { console.log('[-] msebera SSLContextBuilder: ' + e.message); }
    try {
        var TrustStrategy = Java.use('cz.msebera.android.httpclient.conn.ssl.TrustStrategy');
        TrustStrategy.isTrusted.implementation = function(chain, authType) {
            console.log('[+] msebera TrustStrategy.isTrusted() → true');
            return true;
        };
        console.log('[+] cz.msebera TrustStrategy hooked');
    } catch(e) { console.log('[-] msebera TrustStrategy: ' + e.message); }
    try {
        var AbstractVerifier = Java.use('cz.msebera.android.httpclient.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overloads.forEach(function(ov) {
            ov.implementation = function() {
                console.log('[+] msebera AbstractVerifier.verify() → pass');
            };
        });
        console.log('[+] cz.msebera AbstractVerifier hooked');
    } catch(e) { console.log('[-] msebera AbstractVerifier: ' + e.message); }
    setTimeout(function() {
        try {
            Java.choose('cz.msebera.android.httpclient.conn.ssl.SSLContextBuilder$TrustManagerDelegate', {
                onMatch: function(obj) {
                    try {
                        obj.checkServerTrusted.implementation = function() {
                            console.log('[+] msebera TrustManagerDelegate heap patched');
                        };
                    } catch(_) {}
                },
                onComplete: function() { console.log('[+] msebera heap scan done'); }
            });
        } catch(_) {}
    }, 2500);
    try {
        var SSLSocketFactory = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory');
        SSLSocketFactory.isHostnameVerified.implementation = function(host, cert) {
            console.log('[+] msebera isHostnameVerified → true: ' + host);
            return true;
        };
        console.log('[+] cz.msebera SSLSocketFactory.isHostnameVerified hooked');
    } catch(e) { console.log('[-] msebera SSLSocketFactory: ' + e.message); }
    try {
        var SSLSocketFactory2 = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory');
        SSLSocketFactory2.setHostnameVerifier.implementation = function(verifier) {
            console.log('[+] msebera setHostnameVerifier called — injecting ALLOW_ALL');
            var allowAll = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory').ALLOW_ALL_HOSTNAME_VERIFIER.value;
            this.setHostnameVerifier(allowAll);
        };
        console.log('[+] cz.msebera SSLSocketFactory.setHostnameVerifier hooked');
    } catch(e) { console.log('[-] msebera setHostnameVerifier: ' + e.message); }
    try {
        var MySSLSocketFactory = Java.use('com.macom.chitsqpaynew.utilities.MySSLSocketFactory');
        MySSLSocketFactory.getFixedSocketFactory.implementation = function() {
            console.log('[+] MySSLSocketFactory.getFixedSocketFactory() called');
            return this.getFixedSocketFactory();
        };
        console.log('[+] MySSLSocketFactory.getFixedSocketFactory hooked');
    } catch(e) { console.log('[-] MySSLSocketFactory: ' + e.message); }
    try {
        var TMDelegate = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLContextBuilder$TrustManagerDelegate');
        TMDelegate.checkServerTrusted.implementation = function(chain, authType) {
            console.log('[+] msebera TrustManagerDelegate.checkServerTrusted() bypassed');
        };
        console.log('[+] cz.msebera TrustManagerDelegate hooked');
    } catch(e) { console.log('[-] msebera TrustManagerDelegate: ' + e.message); }
    try {
        var AbstractVerifier = Java.use('cz.msebera.android.httpclient.conn.ssl.AbstractVerifier');
        AbstractVerifier.verify.overloads.forEach(function(ov) {
            ov.implementation = function() {
                console.log('[+] msebera AbstractVerifier.verify() → pass');
            };
        });
        console.log('[+] cz.msebera AbstractVerifier hooked');
    } catch(e) { console.log('[-] msebera AbstractVerifier: ' + e.message); }
    try {
        var AsyncHttpClient = Java.use('com.loopj.android.http.AsyncHttpClient');
        AsyncHttpClient.$init.overload('boolean', 'int', 'int')
            .implementation = function(z, httpPort, httpsPort) {
                console.log('[+] AsyncHttpClient constructor → forcing insecure=true');
                this.$init(true, httpPort, httpsPort); // force trust-all
            };
        console.log('[+] loopj AsyncHttpClient constructor hooked');
    } catch(e) { console.log('[-] AsyncHttpClient constructor: ' + e.message); }
    try {
        var AsyncHttpClient2 = Java.use('com.loopj.android.http.AsyncHttpClient');
        AsyncHttpClient2.$init.overload()
            .implementation = function() {
                console.log('[+] AsyncHttpClient() → forcing insecure mode');
                this.$init(true, 80, 443);
            };
        console.log('[+] loopj AsyncHttpClient() no-arg constructor hooked');
    } catch(e) { console.log('[-] AsyncHttpClient no-arg: ' + e.message); }
    setTimeout(function() {
        try {
            Java.choose('cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory', {
                onMatch: function(obj) {
                    try {
                        var allowAll = Java.use('cz.msebera.android.httpclient.conn.ssl.SSLSocketFactory')
                            .ALLOW_ALL_HOSTNAME_VERIFIER.value;
                        obj.setHostnameVerifier(allowAll);
                        console.log('[+] msebera SSLSocketFactory heap: ALLOW_ALL injected');
                    } catch(_) {}
                },
                onComplete: function() { console.log('[+] msebera SSLSocketFactory heap scan done'); }
            });
        } catch(_) {}
        try {
            Java.choose('cz.msebera.android.httpclient.conn.ssl.SSLContextBuilder$TrustManagerDelegate', {
                onMatch: function(obj) {
                    try {
                        obj.checkServerTrusted.implementation = function() {
                            console.log('[+] msebera TrustManagerDelegate heap patched');
                        };
                    } catch(_) {}
                },
                onComplete: function() {}
            });
        } catch(_) {}
    }, 2500);
    console.log('    Package  : com.macom.chitsqpaynew');
    console.log('    Signature: bypassed (getAppSignature no-op)');
    console.log('    Root     : RootUtil.isDeviceRooted() → false');
    console.log('    SSL      : OkHttp3 + conscrypt + NSC bypassed');
    console.log('    Intercept traffic in Burp now.\n');
});