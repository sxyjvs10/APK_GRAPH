"use strict";
function safeStr(p,n){
  try{if(!p||p.isNull())return null;p.readU8();return p.readUtf8String(n||128);}
  catch(_){return null;}
}
function modOf(a){
  try{var m=Process.findModuleByAddress(a);return m?m.name:"?";}catch(_){return "?";}
}
(function(){
  var sp=Module.findExportByName("libc.so","strstr");
  if(!sp){console.log("[-] strstr not found");return;}
  Interceptor.attach(sp,{
    onEnter:function(a){
      this._skip=false;
      try{
        if(a[0].isNull()||a[1].isNull()){this._skip=true;return;}
        var b0=a[1].readU8(), b1=a[1].add(1).readU8();
        if(b1===0x00&&b0>0x1f&&b0<0x7f){this._skip=true;return;}
        if(b0===0||b0>127){this._skip=true;return;}
      }catch(_){this._skip=true;}
    },
    onLeave:function(ret){if(this._skip)ret.replace(ptr(0));}
  });
  console.log("[+] strstr EGL fix active");
})();
(function(){
  ["pthread_kill","raise","tgkill"].forEach(function(s){
    var p=Module.findExportByName("libc.so",s);if(!p)return;
    Interceptor.attach(p,{onEnter:function(a){
      var sig=(s==="raise")?a[0].toInt32():a[1].toInt32();
      if(sig===6||sig===9||sig===15){
        console.log("[!]"+s+"("+sig+")");
        if(s==="raise")a[0]=ptr(0);else a[1]=ptr(0);
      }
    }});
  });
  var kp=Module.findExportByName("libc.so","kill");
  if(kp)Interceptor.attach(kp,{onEnter:function(a){
    if(a[0].toInt32()===Process.id&&(a[1].toInt32()===6||a[1].toInt32()===9))a[1]=ptr(0);
  }});
  ["_exit","_Exit","exit"].forEach(function(s){
    var p=Module.findExportByName("libc.so",s);if(!p)return;
    Interceptor.attach(p,{onEnter:function(a){
      console.log("[!]"+s+"("+a[0].toInt32()+") from "+modOf(this.returnAddress));
      a[0]=ptr(0);
    }});
  });
  var sc=Module.findExportByName("libc.so","syscall");
  if(sc)Interceptor.attach(sc,{onEnter:function(a){
    var nr=a[0].toInt32();
    if(nr===231||nr===60){console.log("[!]syscall("+nr+")");a[0]=ptr(1);}
  }});
  console.log("[+] Kill suppressors armed");
})();
var _hb=["/data/local/tmp/frida","/data/local/tmp/re.frida",
         "/data/local/tmp/frida-server","/system/bin/frida-server"];
(function(){
  var fp=Module.findExportByName("libc.so","fopen");
  if(fp)Interceptor.attach(fp,{onEnter:function(a){
    var p=safeStr(a[0]);
    if(p&&_hb.some(function(b){return p.indexOf(b)===0;})){
      console.log("[*] fopen blocked: "+p);
      a[0]=Memory.allocUtf8String("/dev/null");
    }
  }});
  console.log("[+] fopen block armed");
})();
var _hooked={};
function hookAllExports(mod){
  if(_hooked[mod.name])return;
  _hooked[mod.name]=true;
  var exps=mod.enumerateExports();
  console.log("\n===== "+mod.name+" @ "+mod.base+" exports="+exps.length+" =====");
  exps.forEach(function(e){
    console.log("  "+e.address+"  "+e.type+"  "+e.name);
  });
  var n=0;
  exps.forEach(function(e){
    if(e.type!=="function")return;
    try{
      Interceptor.attach(e.address,{
        onEnter:function(){
          if(!this._e){this._e=true;console.log("[CALL] "+mod.name+"!"+e.name);}
        },
        onLeave:function(r){
          if(!this._l){this._l=true;
            var v=r.toInt32();
            console.log("[RET]  "+mod.name+"!"+e.name+"="+v);
            if(v!==0&&v>=-1&&v<=255){r.replace(ptr(0));console.log("  [BYPASSED->0]");}
          }
        }
      });n++;
    }catch(_){}
  });
  console.log("[+] "+mod.name+": "+n+" hooks active\n");
}
function hookClib(mod){
  if(_hooked["clib_ssl"])return; _hooked["clib_ssl"]=true;
  console.log("\n===== libclib.so SSL @ "+mod.base+" =====");
  ["ssl_verify_cert_chain","SSL_verify_client_post_handshake",
   "X509_verify_cert","X509_verify",
   "ssl_do_handshake","SSL_do_handshake"].forEach(function(name){
    var a=Module.findExportByName(mod.name,name);
    if(!a){console.log("  [-] "+name);return;}
    try{
      Interceptor.attach(a,{
        onLeave:function(r){
          console.log("[SSL] "+name+"="+r.toInt32()+"->1");
          r.replace(ptr(1));
        }
      });
      console.log("  [+] "+name);
    }catch(e){console.log("  [-] "+name+": "+e.message);}
  });
  var scv=Module.findExportByName(mod.name,"SSL_CTX_set_custom_verify");
  if(scv){
    var noop=new NativeCallback(function(){return 1;},"int",["pointer","pointer"]);
    Interceptor.attach(scv,{onEnter:function(a){
      console.log("[SSL] SSL_CTX_set_custom_verify -> noop");
      if(!a[2].isNull())a[2]=noop;
    }});
    console.log("  [+] SSL_CTX_set_custom_verify");
  }
}
var _libHandlers={
  "libtmlib.so":       hookAllExports,
  "libsecurity.so":    hookAllExports,
  "libtoolChecker.so": hookAllExports,
  "libpolarssl.so":    hookAllExports,
  "libclib.so":        function(m){hookClib(m);hookAllExports(m);},
};
var _pollCount=0;
var _allHooked=false;
var _pollTimer=setInterval(function(){
  if(_allHooked||++_pollCount>200){clearInterval(_pollTimer);return;}
  var remaining=0;
  Object.keys(_libHandlers).forEach(function(name){
    if(_hooked[name]||(name==="libclib.so"&&_hooked["clib_ssl"])) return;
    var m=Process.findModuleByName(name);
    if(m){
      console.log("[!] CAUGHT: "+name+" at poll #"+_pollCount);
      _libHandlers[name](m);
    } else {
      remaining++;
    }
  });
  if(remaining===0) _allHooked=true;
},100); // Poll every 100ms — much faster than before
[["libdl.so","dlopen"],["libdl.so","android_dlopen_ext"],
 ["libdl_android.so","__loader_dlopen"],
 ["libdl_android.so","__loader_android_dlopen_ext"]
].forEach(function(t){
  var p=Module.findExportByName(t[0],t[1]);if(!p)return;
  Interceptor.attach(p,{
    onEnter:function(a){this._n=safeStr(a[0])||"";},
    onLeave:function(){
      var n=this._n;
      Object.keys(_libHandlers).forEach(function(lib){
        if(n.indexOf(lib.replace(".so",""))!==-1){
          var m=Process.findModuleByName(lib);
          if(m){
            console.log("[dlopen] Caught: "+lib);
            _libHandlers[lib](m);
          } else {
            setTimeout(function(){
              var mm=Process.findModuleByName(lib);
              if(mm){console.log("[dlopen+50ms] Caught: "+lib);_libHandlers[lib](mm);}
            },10);
          }
        }
      });
    }
  });
  console.log("[+] "+t[0]+"!"+t[1]+" hooked");
});
Java.perform(function(){
  function tryJ(l,fn){try{fn();console.log("[+] "+l);}catch(e){console.log("[-] "+l+": "+e.message);}}
  tryJ("FLAG_SECURE",function(){
    Java.use("android.view.Window").setFlags.overload("int","int")
      .implementation=function(f,m){this.setFlags(f&~0x2000,m&~0x2000);};
  });
  tryJ("System.exit()",function(){
    Java.use("java.lang.System").exit.implementation=function(c){
      console.log("[!]System.exit("+c+")");};
  });
  tryJ("Runtime.exit/halt()",function(){
    var RT=Java.use("java.lang.Runtime");
    ["exit","halt"].forEach(function(m){
      try{RT[m].overloads.forEach(function(ov){
        ov.implementation=function(c){console.log("[!]Runtime."+m+"("+c+")");};
      });}catch(_){}
    });
  });
  tryJ("Process.killProcess()",function(){
    Java.use("android.os.Process").killProcess.implementation=function(p){
      console.log("[!]killProcess("+p+")");};
  });
  tryJ("Build spoof",function(){
    var B=Java.use("android.os.Build");
    B.FINGERPRINT.value="google/walleye/walleye:8.1.0/OPM1.171019.011/4448085:user/release-keys";
    B.MODEL.value="Pixel 2";B.MANUFACTURER.value="Google";B.BRAND.value="google";
    B.DEVICE.value="walleye";B.PRODUCT.value="walleye";B.HARDWARE.value="walleye";
    B.TAGS.value="release-keys";
    Java.use("android.os.Build$VERSION").RELEASE.value="8.1.0";
  });
  tryJ("Debug.isDebuggerConnected()",function(){
    Java.use("android.os.Debug").isDebuggerConnected.implementation=function(){return false;};
  });
  tryJ("Debug.waitingForDebugger()",function(){
    Java.use("android.os.Debug").waitingForDebugger.implementation=function(){return false;};
  });
  tryJ("Thread.getName()",function(){
    Java.use("java.lang.Thread").getName.implementation=function(){
      var n=this.getName();
      return(n&&/frida|gum-js|gmain|gdbus/.test(n))?"main":n;
    };
  });
  tryJ("BufferedReader",function(){
    Java.use("java.io.BufferedReader").readLine.overload().implementation=function(){
      var l=this.readLine();
      return(l&&(l.indexOf("27042")!==-1||l.indexOf("27043")!==-1))?"":l;
    };
  });
  tryJ("File.exists()",function(){
    var rp=["/system/bin/su","/system/xbin/su","/sbin/su",
            "/data/local/su","/data/local/bin/su","/data/local/xbin/su",
            "/data/adb/magisk","/sbin/magisk","/system/app/Superuser.apk",
            "/system/app/SuperSU","/system/app/MagiskManager"];
    Java.use("java.io.File").exists.implementation=function(){
      var p=this.getAbsolutePath();if(!p)return this.exists();
      if(/frida|gum-js|xposed/.test(p))return false;
      if(rp.some(function(r){return p===r||p.indexOf(r)===0;}))return false;
      return this.exists();
    };
  });
  tryJ("Runtime.exec()",function(){
    var bl=["su","magisk","busybox","supersu","frida"];
    var RT=Java.use("java.lang.Runtime");
    RT.exec.overload("java.lang.String").implementation=function(cmd){
      if(cmd&&bl.some(function(b){return cmd.indexOf(b)!==-1;})){
        console.log("[*] exec blocked: "+cmd);return this.exec("echo");
      }
      return this.exec(cmd);
    };
  });
  tryJ("ProcessBuilder",function(){
    var bad=["ro.secure","ro.debuggable","ro.hardware.virtual_device",
             "persist.magisk.hide","qemu.sf.fake_camera","init.svc.qemud",
             "ro.build.selinux","ro.boot.selinux"];
    Java.use("java.lang.ProcessBuilder").start.implementation=function(){
      var cmd=this.command().toArray().join(" ");
      if(bad.some(function(p){return cmd.indexOf(p)!==-1;}))
        return Java.use("java.lang.Runtime").getRuntime().exec("echo");
      return this.start();
    };
  });
  tryJ("conscrypt.TrustManagerImpl.verifyChain()",function(){
    Java.use("com.android.org.conscrypt.TrustManagerImpl")
      .verifyChain.implementation=function(u,t,h,c,o,s){return u;};
  });
  tryJ("conscrypt checkTrusted",function(){
    var T=Java.use("com.android.org.conscrypt.TrustManagerImpl");
    ["checkTrusted","checkServerTrusted","checkClientTrusted"].forEach(function(m){
      try{T[m].overloads.forEach(function(ov){ov.implementation=function(){};});}catch(_){}
    });
  });
  tryJ("NetworkSecurityTrustManager",function(){
    var N=Java.use("android.security.net.config.NetworkSecurityTrustManager");
    N.checkServerTrusted.overloads.forEach(function(ov){ov.implementation=function(){};});
    N.checkPins.implementation=function(){};
  });
  tryJ("RootTrustManager",function(){
    Java.use("android.security.net.config.RootTrustManager")
      .checkServerTrusted.overloads.forEach(function(ov){ov.implementation=function(){};});
  });
  tryJ("SSLContext.init()",function(){
    Java.use("javax.net.ssl.SSLContext").init
      .overload("[Ljavax.net.ssl.KeyManager;","[Ljavax.net.ssl.TrustManager;","java.security.SecureRandom")
      .implementation=function(km,tm,sr){
        try{this.init(km,null,sr);}catch(_){try{this.init(km,tm,sr);}catch(__){}}
      };
  });
  tryJ("CertificatePinner",function(){
    Java.use("com.android.okhttp.CertificatePinner")
      .check.overloads.forEach(function(ov){ov.implementation=function(){};});
  });
  tryJ("OkHostnameVerifier",function(){
    Java.use("com.android.org.conscrypt.OkHostnameVerifier")
      .verify.overloads.forEach(function(ov){ov.implementation=function(){return true;};});
  });
  tryJ("HttpsURLConnection",function(){
    var H=Java.use("javax.net.ssl.HttpsURLConnection");
    H.setDefaultHostnameVerifier.implementation=function(){};
    H.setDefaultSSLSocketFactory.implementation=function(){};
  });
  setTimeout(function(){
    try{Java.choose("javax.net.ssl.X509TrustManager",{
      onMatch:function(obj){
        try{obj.checkServerTrusted.overloads.forEach(function(ov){ov.implementation=function(){};});}catch(_){}
      },onComplete:function(){}
    });}catch(_){}
  },3000);
  setTimeout(function(){
    try{
      Java.enumerateLoadedClasses({
        onMatch:function(name){
          if(/talsec|aheaditec/i.test(name)){
            console.log("[Talsec] Class found: "+name);
          }
        },
        onComplete:function(){console.log("[*] Talsec class scan done");}
      });
    }catch(_){}
  },2000);
  console.log("[+] Java layer armed");
});
global.dumpLib=function(name){
  var m=Process.findModuleByName(name);if(!m){console.log("not loaded");return;}
  console.log(name+" @ "+m.base);
  m.enumerateExports().forEach(function(e){console.log("  "+e.address+"  "+e.type+"  "+e.name);});
};
global.dumpThreads=function(){
  Process.enumerateThreads().forEach(function(t){
    console.log("tid="+t.id+" state="+t.state);
    try{Thread.backtrace(t.context,Backtracer.FUZZY).map(DebugSymbol.fromAddress)
      .forEach(function(f){console.log("  "+f);});}catch(_){}
  });
};
global.listModules=function(){
  Process.enumerateModules().forEach(function(m){console.log(m.name+"\t"+m.base+"\t"+m.size);});
};
global.patchAddress=function(h,v){
  Interceptor.attach(ptr(h),{onLeave:function(r){r.replace(ptr(v||0));console.log("[+] patched "+h);}});
};
global.enumerateClasses=function(kw){
  Java.enumerateLoadedClasses({
    onMatch:function(n){if(n.toLowerCase().indexOf(kw.toLowerCase())!==-1)console.log(n);},
    onComplete:function(){console.log("done");}
  });
};
console.log("\n[+] FINAL BYPASS v2 ARMED");
console.log("    EGL fix     : strstr UTF-16 guard");
console.log("    Polling     : every 100ms (aggressive)");
console.log("    Security    : libtmlib+libsecurity+libtoolChecker+libclib");
console.log("    Java        : full bypass");
console.log("\n[IMPORTANT] When app loads, watch for:");
console.log("  [CAUGHT] lines = security libs detected");
console.log("  [CALL]   lines = security functions invoked");
console.log("  [!]      lines = kill attempts\n");