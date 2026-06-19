setTimeout(function() {
  Java.perform(function() {
    console.log("[APKGraph] Root Detection Bypass");
    console.log("[APKGraph] Hooking all known root detection methods...\n");
    var bypassed = [];
    var rootBeerClasses = [
      "com.scottyab.rootbeer.RootBeer",
      "com.scottyab.rootbeer.util.Utils",
    ];
    rootBeerClasses.forEach(function(cls) {
      try {
        var RootBeer = Java.use(cls);
        var methods = RootBeer.class.getDeclaredMethods();
        methods.forEach(function(method) {
          var retType = method.getReturnType().getName();
          if (retType === "boolean") {
            try {
              RootBeer[method.getName()].implementation = function() {
                console.log("[+] RootBeer." + method.getName() + "() → false");
                return false;
              };
            } catch(e) {}
          }
        });
        bypassed.push("RootBeer (" + cls + ")");
      } catch(e) {}
    });
    try {
      var File = Java.use("java.io.File");
      var suspiciousPaths = [
        "/system/bin/su", "/system/xbin/su", "/sbin/su",
        "/su/bin/su", "/system/su",
        "/system/bin/busybox", "/system/xbin/busybox",
        "/sbin/magisk", "/sbin/.magisk",
        "/data/adb/magisk", "/system/bin/magisk",
        "/system/xbin/which",
        "/proc/net/xt_qtaguid", // Xposed indicator
      ];
      File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        if (suspiciousPaths.indexOf(path) !== -1) {
          console.log("[+] File.exists() blocked for: " + path + " → false");
          return false;
        }
        return this.exists();
      };
      File.canExecute.implementation = function() {
        var path = this.getAbsolutePath();
        if (suspiciousPaths.some(function(p) { return path.indexOf(p) !== -1; })) {
          console.log("[+] File.canExecute() blocked for: " + path + " → false");
          return false;
        }
        return this.canExecute();
      };
      bypassed.push("java.io.File (su/busybox/magisk paths)");
    } catch(e) {}
    try {
      var Build = Java.use("android.os.Build");
      Object.defineProperty(Build, "TAGS", {
        get: function() {
          console.log("[+] Build.TAGS → release-keys (spoofed)");
          return "release-keys";
        }
      });
      bypassed.push("android.os.Build.TAGS");
    } catch(e) {}
    try {
      var SystemProperties = Java.use("android.os.SystemProperties");
      SystemProperties.get.overload("java.lang.String").implementation = function(key) {
        var val = this.get(key);
        if (key === "ro.debuggable" || key === "ro.secure") {
          console.log("[+] SystemProperties.get(" + key + ") spoofed");
          return key === "ro.debuggable" ? "0" : "1";
        }
        if (key === "ro.build.tags" || key === "ro.build.type") {
          console.log("[+] SystemProperties.get(" + key + ") → release (spoofed)");
          return key === "ro.build.tags" ? "release-keys" : "user";
        }
        return val;
      };
      SystemProperties.get.overload("java.lang.String", "java.lang.String").implementation = function(key, def) {
        var val = this.get(key, def);
        if (key === "ro.debuggable") return "0";
        if (key === "ro.build.tags") return "release-keys";
        return val;
      };
      bypassed.push("SystemProperties (ro.debuggable, ro.build.tags)");
    } catch(e) {}
    try {
      var rootPackages = [
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "eu.chainfire.supersu",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "com.yellowes.su",
        "com.kingroot.kinguser",
        "com.kingo.root",
        "com.smedialink.oneclickroot",
        "com.zhiqupk.root.global",
        "com.alephzain.framaroot",
      ];
      var PackageManager = Java.use("android.app.ApplicationPackageManager");
      PackageManager.getPackageInfo.implementation = function(packageName, flags) {
        if (rootPackages.indexOf(packageName) !== -1) {
          console.log("[+] PackageManager.getPackageInfo(" + packageName + ") → NameNotFoundException");
          var ex = Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(packageName);
          throw ex;
        }
        return this.getPackageInfo(packageName, flags);
      };
      bypassed.push("PackageManager (Magisk/SuperSU packages)");
    } catch(e) {}
    try {
      var Runtime = Java.use("java.lang.Runtime");
      Runtime.exec.overload("java.lang.String").implementation = function(cmd) {
        if (cmd && (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 || cmd === "id")) {
          console.log("[+] Runtime.exec(" + cmd + ") blocked (root check) → fake empty result");
          return Runtime.exec.call(this, "echo ''");
        }
        return this.exec(cmd);
      };
      Runtime.exec.overload("[Ljava.lang.String;").implementation = function(cmdArray) {
        if (cmdArray && cmdArray.length > 0) {
          var cmd = cmdArray[0];
          if (cmd && (cmd.indexOf("/su") !== -1 || cmd.indexOf("busybox") !== -1)) {
            console.log("[+] Runtime.exec([" + cmd + "]) blocked");
            return Runtime.exec.call(this, "echo ''");
          }
        }
        return this.exec(cmdArray);
      };
      bypassed.push("Runtime.exec (su/busybox commands)");
    } catch(e) {}
    try {
      var SafetyNetClient = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
      SafetyNetClient.attest.implementation = function(nonce, apiKey) {
        console.log("[+] SafetyNet.attest() intercepted — note: cannot fully spoof server-side validation");
        return this.attest(nonce, apiKey);
      };
      bypassed.push("SafetyNet attest (intercepted)");
    } catch(e) {}
    try {
      var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
      ProcessBuilder.start.implementation = function() {
        var cmd = this.command().toString();
        if (cmd.indexOf("frida") !== -1 || cmd.indexOf("xposed") !== -1) {
          console.log("[+] ProcessBuilder blocked Frida/Xposed detection: " + cmd);
          throw Java.use("java.io.IOException").$new("Permission denied");
        }
        return this.start();
      };
      bypassed.push("ProcessBuilder (Frida/Xposed self-detection)");
    } catch(e) {}
    var rootCheckMethodNames = ["isRooted", "isDeviceRooted", "isRootAvailable", "checkRoot",
                                 "isRootPresent", "hasRootAccess", "checkForRoot", "deviceIsRooted"];
    Java.enumerateLoadedClasses({
      onMatch: function(className) {
        try {
          var cls = Java.use(className);
          rootCheckMethodNames.forEach(function(methodName) {
            try {
              var methods = cls[methodName];
              if (methods) {
                var retType = cls.class.getDeclaredMethod(methodName).getReturnType().getName();
                if (retType === "boolean" || retType === "java.lang.Boolean") {
                  cls[methodName].implementation = function() {
                    console.log("[+] " + className + "." + methodName + "() → false");
                    return false;
                  };
                }
              }
            } catch(e) {}
          });
        } catch(e) {}
      },
      onComplete: function() {}
    });
    console.log("\n[APKGraph] Root Detection Bypass complete. Hooks installed:");
    bypassed.forEach(function(b) { console.log("  ✓ " + b); });
    console.log("  ✓ Custom isRooted/checkRoot methods (dynamic enumeration)\n");
  });
}, 0);
