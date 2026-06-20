
/*
 * Targeted Bypass for com.q.security_sdk
 *
 * This script specifically targets the integrity check causing the "Unsupported Device"
 * message and application exit.
 */

setTimeout(function() {
    Java.perform(function() {

        console.log("");
        console.log("[.] Targeted Bypass for com.q.security_sdk");

        /*
         * ========== The Main Bypass ==========
         *
         * This section hooks the results of the DeviceIntegrityCheck and forces
         * them to return 'false', indicating a "clean" device.
         */
        console.log("[+] Applying bypass for com.q.security_sdk...");
        try {
            var DeviceIntegrityCheck = Java.use("com.q.security_sdk.main.DeviceIntegrityCheck");

            DeviceIntegrityCheck.getCheckMethodOne.implementation = function() {
                console.log("[+] Bypassing DeviceIntegrityCheck.getCheckMethodOne()");
                return false;
            };
            DeviceIntegrityCheck.getCheckMethodTwo.implementation = function() {
                console.log("[+] Bypassing DeviceIntegrityCheck.getCheckMethodTwo()");
                return false;
            };
            DeviceIntegrityCheck.getCheckMethodThree.implementation = function() {
                console.log("[+] Bypassing DeviceIntegrityCheck.getCheckMethodThree()");
                return false;
            };
            DeviceIntegrityCheck.getCheckMethodFour.implementation = function() {
                console.log("[+] Bypassing DeviceIntegrityCheck.getCheckMethodFour()");
                return false;
            };
            DeviceIntegrityCheck.getCheckMethodFive.implementation = function() {
                console.log("[+] Bypassing DeviceIntegrityCheck.getCheckMethodFive()");
                return false;
            };

        } catch (e) {
            console.log("[-] Failed to apply bypass for com.q.security_sdk: " + e.message);
        }
        
        /*
         * ========== SSL PINNING BYPASS (Keep this for network traffic) ==========
         */
        console.log("[.] Bypassing SSL Pinning...");

        try {
            var TrustAllManager = Java.registerClass({
                name: 'dev.gemini.TrustAllManagerV2',
                implements: [Java.use("javax.net.ssl.X509TrustManager")],
                methods: {
                    checkClientTrusted: function(chain, authType) {},
                    checkServerTrusted: function(chain, authType) {},
                    getAcceptedIssuers: function() { return []; }
                }
            });
             var AcceptAllHostnameVerifier = Java.registerClass({
                name: 'dev.gemini.AcceptAllHostnameVerifierV2',
                implements: [Java.use("javax.net.ssl.HostnameVerifier")],
                methods: {
                    verify: function(hostname, session) { return true; }
                }
            });

            var OkHttpClientBuilder = Java.use("okhttp3.OkHttpClient$Builder");
            OkHttpClientBuilder.build.implementation = function() {
                console.log("[+] OkHttp3 Client Builder detected. Patching...");
                var TrustManagers = [ TrustAllManager.$new() ];
                var SSLContext = Java.use("javax.net.ssl.SSLContext");
                var context = SSLContext.getInstance("TLS");
                context.init(null, TrustManagers, null);
                this.sslSocketFactory(context.getSocketFactory(), TrustManagers[0]);
                this.hostnameVerifier(AcceptAllHostnameVerifier.$new());
                return this.build.call(this);
            };

        } catch (e) {
            console.log("[-] OkHttp3 bypass error: " + e.message);
        }
        
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            var ArrayList = Java.use("java.util.ArrayList");

            TrustManagerImpl.checkTrustedRecursive.implementation = function(certs, ocspData, sctData, host, clientAuth) {
                console.log("[+] Bypassing Conscrypt checkTrustedRecursive for: " + host);
                return ArrayList.$new();
            }

        } catch (e) {
            console.log("[-] Conscrypt bypass error: " + e.message);
        }


        /*
         * ========== Optional: Crude System.exit() bypass ==========
         *
         * Uncomment the block below ONLY if the app still closes.
         * This is a brute-force method.
         */
        /*
        try {
            var System = Java.use('java.lang.System');
            System.exit.implementation = function(status) {
                console.log('[!] System.exit(' + status + ') called, but prevented.');
            }
        } catch (e) {
            console.log('[-] System.exit bypass error: ' + e.message);
        }
        */

    });
}, 0);