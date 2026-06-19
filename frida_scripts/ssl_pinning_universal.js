/*
 * @name         ssl_pinning_universal
 * @bypass       SSL Pinning
 * @targets      OkHttp3, TrustManager, Conscrypt, Network Security Config, TrustKit, Apache HttpClient, WebView
 * @author       APKGraph Built-in
 * @frida_version >= 15.0
 * @description  Universal SSL pinning bypass. Hooks all known pinning implementations.
 *               Supports OkHttp3 CertificatePinner, custom X509TrustManager,
 *               Conscrypt, WebViewClient, TrustKit, and Android native SSL stack.
 * @usage        frida -U -f com.target.app -l ssl_pinning_universal.js --no-pause
 */

setTimeout(function() {
  Java.perform(function() {
    console.log("[APKGraph] SSL Pinning Bypass — Universal");
    console.log("[APKGraph] Hooking all known pinning implementations...\n");

    var bypassed = [];

    // ── 1. OkHttp3 CertificatePinner ───────────────────────────────────────
    try {
      var CertificatePinner = Java.use("okhttp3.CertificatePinner");
      CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
        console.log("[+] OkHttp3 CertificatePinner.check() bypassed for: " + hostname);
        return;
      };
      CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function(hostname, certs) {
        console.log("[+] OkHttp3 CertificatePinner.check(certs) bypassed for: " + hostname);
        return;
      };
      bypassed.push("OkHttp3 CertificatePinner");
    } catch(e) { /* not present */ }

    // ── 2. Custom TrustManager (X509TrustManager) ──────────────────────────
    try {
      var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
      TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
        console.log("[+] Conscrypt TrustManagerImpl.verifyChain() bypassed for: " + host);
        return untrustedChain;
      };
      bypassed.push("Conscrypt TrustManagerImpl");
    } catch(e) { /* not present */ }

    // ── 3. SSLContext TrustManager override ────────────────────────────────
    try {
      var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
      var SSLContext       = Java.use("javax.net.ssl.SSLContext");
      var TrustManager     = Java.registerClass({
        name: "com.apkgraph.bypass.TrustManager",
        implements: [X509TrustManager],
        methods: {
          checkClientTrusted: function(chain, authType) {},
          checkServerTrusted: function(chain, authType) {
            console.log("[+] X509TrustManager.checkServerTrusted() bypassed");
          },
          getAcceptedIssuers: function() { return []; }
        }
      });
      var trustManagers = [TrustManager.$new()];
      var sslCtx = SSLContext.getInstance("TLS");
      sslCtx.init(null, trustManagers, null);
      SSLContext.getDefault.implementation = function() { return sslCtx; };
      bypassed.push("X509TrustManager / SSLContext");
    } catch(e) { /* not present */ }

    // ── 4. OkHttp3 HTTPS hostname verifier ────────────────────────────────
    try {
      var OkHostnameVerifier = Java.use("okhttp3.internal.tls.OkHostnameVerifier");
      OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function(hostname, session) {
        console.log("[+] OkHttp3 HostnameVerifier bypassed for: " + hostname);
        return true;
      };
      bypassed.push("OkHttp3 HostnameVerifier");
    } catch(e) { /* not present */ }

    // ── 5. HttpsURLConnection hostnameVerifier ─────────────────────────────
    try {
      var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
      HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
        console.log("[+] HttpsURLConnection.setDefaultHostnameVerifier bypassed");
        return;
      };
      HttpsURLConnection.setSSLSocketFactory.implementation = function(factory) {
        console.log("[+] HttpsURLConnection.setSSLSocketFactory bypassed");
        return;
      };
      bypassed.push("HttpsURLConnection");
    } catch(e) { /* not present */ }

    // ── 6. WebViewClient SSL errors ────────────────────────────────────────
    try {
      var WebViewClient = Java.use("android.webkit.WebViewClient");
      WebViewClient.onReceivedSslError.implementation = function(webview, handler, error) {
        console.log("[+] WebViewClient.onReceivedSslError() bypassed — proceeding");
        handler.proceed();
      };
      bypassed.push("WebViewClient SSL errors");
    } catch(e) { /* not present */ }

    // ── 7. TrustKit (Square) ───────────────────────────────────────────────
    try {
      var TrustKit = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
      TrustKit.checkServerTrusted.implementation = function(chain, authType) {
        console.log("[+] TrustKit PinningTrustManager.checkServerTrusted() bypassed");
      };
      bypassed.push("TrustKit");
    } catch(e) { /* not present */ }

    // ── 8. Appcelerator/Titanium ──────────────────────────────────────────
    try {
      var PinningHostnameVerifier = Java.use("appcelerator.https.PinningHostnameVerifier");
      PinningHostnameVerifier.verify.implementation = function() { return true; };
      bypassed.push("Appcelerator Pinning");
    } catch(e) { /* not present */ }

    // ── 9. Apache HttpClient ──────────────────────────────────────────────
    try {
      var AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
      AbstractVerifier.verify.implementation = function() {
        console.log("[+] Apache HttpClient AbstractVerifier.verify() bypassed");
      };
      bypassed.push("Apache HttpClient");
    } catch(e) { /* not present */ }

    // ── Summary ───────────────────────────────────────────────────────────
    console.log("\n[APKGraph] SSL Bypass complete. Hooks installed:");
    bypassed.forEach(function(b) { console.log("  ✓ " + b); });
    console.log("\n[APKGraph] Route traffic through Burp/mitmproxy on port 8080");
    console.log("[APKGraph] Set proxy: adb shell settings put global http_proxy <your_ip>:8080\n");
  });
}, 0);
