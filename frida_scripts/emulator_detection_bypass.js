setTimeout(function() {
  Java.perform(function() {
    console.log("[APKGraph] Emulator Detection Bypass\n");
    var bypassed = [];
    var buildSpoof = {
      "FINGERPRINT":  "samsung/dreamltexx/dreamlte:9/PPR1.180610.011/G950FXXS5DSI2:user/release-keys",
      "MODEL":        "SM-G950F",
      "MANUFACTURER": "samsung",
      "BRAND":        "samsung",
      "DEVICE":       "dreamlte",
      "PRODUCT":      "dreamltexx",
      "HARDWARE":     "samsungexynos8895",
      "BOARD":        "SRPOB28A003KU",
      "HOST":         "SEP-132",
    };
    try {
      var Build = Java.use("android.os.Build");
      Object.keys(buildSpoof).forEach(function(field) {
        try {
          Object.defineProperty(Build, field, {
            get: function() {
              return buildSpoof[field];
            }
          });
        } catch(e) {}
      });
      bypassed.push("android.os.Build (FINGERPRINT, MODEL, MANUFACTURER...)");
    } catch(e) {}
    try {
      var TelephonyManager = Java.use("android.telephony.TelephonyManager");
      TelephonyManager.getDeviceId.overload().implementation = function() {
        return "352339081380345"; // Real IMEI
      };
      TelephonyManager.getImei.overload().implementation = function() {
        return "352339081380345";
      };
      TelephonyManager.getSubscriberId.overload().implementation = function() {
        return "310260000000000"; // AT&T IMSI
      };
      TelephonyManager.getLine1Number.overload().implementation = function() {
        return "+15555555555";
      };
      TelephonyManager.getNetworkOperatorName.overload().implementation = function() {
        return "AT&T";
      };
      TelephonyManager.getPhoneType.overload().implementation = function() {
        return 1; // PHONE_TYPE_GSM
      };
      bypassed.push("TelephonyManager (IMEI, IMSI, operator)");
    } catch(e) {}
    try {
      var WifiInfo = Java.use("android.net.wifi.WifiInfo");
      WifiInfo.getSSID.implementation = function() { return "\"HomeWifi\""; };
      WifiInfo.getBSSID.implementation = function() { return "de:ad:be:ef:00:01"; };
      WifiInfo.getMacAddress.implementation = function() { return "de:ad:be:ef:00:01"; };
      bypassed.push("WifiInfo (SSID, BSSID, MAC)");
    } catch(e) {}
    console.log("[APKGraph] Emulator Bypass complete:");
    bypassed.forEach(function(b) { console.log("  ✓ " + b); });
    console.log();
  });
}, 0);
