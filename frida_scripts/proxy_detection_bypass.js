setTimeout(function() {
  Java.perform(function() {
    console.log("[APKGraph] Proxy Detection Bypass");
    console.log("[APKGraph] Hooking all proxy/VPN detection methods...\n");
    var bypassed = [];
    try {
      var System = Java.use("java.lang.System");
      System.getProperty.overload("java.lang.String").implementation = function(key) {
        if (key === "http.proxyHost" || key === "https.proxyHost") {
          console.log("[+] System.getProperty(" + key + ") → null (proxy hidden)");
          return null;
        }
        if (key === "http.proxyPort" || key === "https.proxyPort") {
          console.log("[+] System.getProperty(" + key + ") → null (proxy port hidden)");
          return null;
        }
        return this.getProperty(key);
      };
      System.getProperty.overload("java.lang.String", "java.lang.String").implementation = function(key, def) {
        if (key === "http.proxyHost" || key === "https.proxyHost") return null;
        if (key === "http.proxyPort" || key === "https.proxyPort") return null;
        return this.getProperty(key, def);
      };
      bypassed.push("System.getProperty (http.proxyHost/Port)");
    } catch(e) {}
    try {
      var ProxySelector = Java.use("java.net.ProxySelector");
      var Proxy         = Java.use("java.net.Proxy");
      var ArrayList     = Java.use("java.util.ArrayList");
      ProxySelector.select.implementation = function(uri) {
        console.log("[+] ProxySelector.select() → Proxy.NO_PROXY for: " + uri);
        var list = ArrayList.$new();
        list.add(Proxy.NO_PROXY.value);
        return list;
      };
      bypassed.push("ProxySelector.select()");
    } catch(e) {}
    try {
      var ConnectivityManager = Java.use("android.net.ConnectivityManager");
      ConnectivityManager.getDefaultProxy.implementation = function() {
        console.log("[+] ConnectivityManager.getDefaultProxy() → null");
        return null;
      };
      bypassed.push("ConnectivityManager.getDefaultProxy()");
    } catch(e) {}
    try {
      var NetworkInfo = Java.use("android.net.NetworkInfo");
      var ConnectivityManagerClass = Java.use("android.net.ConnectivityManager");
      ConnectivityManagerClass.getNetworkInfo.implementation = function(networkType) {
        var result = this.getNetworkInfo(networkType);
        if (networkType === 17) {
          console.log("[+] getNetworkInfo(TYPE_VPN) → null (VPN hidden)");
          return null;
        }
        return result;
      };
      bypassed.push("ConnectivityManager.getNetworkInfo (TYPE_VPN)");
    } catch(e) {}
    try {
      var Network          = Java.use("android.net.Network");
      var NetworkCapabilities = Java.use("android.net.NetworkCapabilities");
      var ConnMgr2         = Java.use("android.net.ConnectivityManager");
      ConnMgr2.getNetworkCapabilities.implementation = function(network) {
        var caps = this.getNetworkCapabilities(network);
        if (caps !== null) {
          try {
            var hasVpn = !caps.hasCapability(15);
            if (hasVpn) {
              console.log("[+] VPN NetworkCapabilities blocked");
              return null;
            }
          } catch(e) {}
        }
        return caps;
      };
      bypassed.push("NetworkCapabilities VPN filtering");
    } catch(e) {}
    try {
      var InetSocketAddress = Java.use("java.net.InetSocketAddress");
      InetSocketAddress.getHostName.implementation = function() {
        var host = this.getHostName();
        if (host && (host === "127.0.0.1" || host === "localhost" || host.indexOf("10.") === 0 || host.indexOf("192.168.") === 0)) {
          console.log("[!] InetSocketAddress.getHostName() = " + host + " (possible proxy check)");
        }
        return host;
      };
      bypassed.push("InetSocketAddress.getHostName (logging)");
    } catch(e) {}
    try {
      var OkHttpClient_Builder = Java.use("okhttp3.OkHttpClient$Builder");
      OkHttpClient_Builder.proxy.implementation = function(proxy) {
        console.log("[+] OkHttpClient.Builder.proxy() call intercepted");
        return this.proxy(proxy);
      };
      bypassed.push("OkHttp3 Client proxy setting (logged)");
    } catch(e) {}
    try {
      var AndroidProxy = Java.use("android.net.Proxy");
      AndroidProxy.getHost.overload("android.content.Context").implementation = function(ctx) {
        console.log("[+] android.net.Proxy.getHost() → null");
        return null;
      };
      AndroidProxy.getPort.overload("android.content.Context").implementation = function(ctx) {
        console.log("[+] android.net.Proxy.getPort() → -1");
        return -1;
      };
      bypassed.push("android.net.Proxy.getHost/Port()");
    } catch(e) {}
    console.log("\n[APKGraph] Proxy Detection Bypass complete. Hooks installed:");
    bypassed.forEach(function(b) { console.log("  ✓ " + b); });
    console.log("\n[APKGraph] Tip: Combine with ssl_pinning_universal.js for full traffic interception\n");
  });
}, 0);
