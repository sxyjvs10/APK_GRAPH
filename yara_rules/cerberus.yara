rule Android_Banker_Cerberus {
    meta:
        description = "Detects Android Cerberus Banking Trojan strings"
        severity = "Critical"
    strings:
        $s1 = "bot_id"
        $s2 = "bot_ver"
        $s3 = "Cerberus" nocase
        $s4 = "AccessibilityService"
    condition:
        all of them
}
