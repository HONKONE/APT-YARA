rule APT_Oilrig_Feb2_OopsIE : RAT_OopsIE
{
    meta:
        author = "HONKONE"
        description = "OopsIE use by Oilrig in February 2018"
        date = "2018-02-10"
    strings:
        $TaskName = "IntelSecurityManager.exe" wide ascii nocase
        $FileName_1 = "srvCheckresponded.tmp" wide ascii nocase
        $FileName_2 = "srvResesponded.vbs" wide ascii nocase
        $FileName_3 = "tmpCa.vbs" wide ascii nocase
        $CC = "http://www.msoffice365cdn.com/" wide ascii nocase
        $HttpRequest = "InternetExplorer"
        $HttpArg_1 = "AAZ" wide ascii nocase
        $HttpArg_2 = "AAZFinish" wide ascii nocase
        $HttpArg_3 = "AAZUploaded" wide ascii nocase
        $HttpArg_4 = "ABZ" wide ascii nocase
        $HttpArg_5 = "ABZFinish" wide ascii nocase
    condition:
        $TaskName and all of ($FileName_*) and $CC and $HttpRequest and all of ($HttpArg_*)
}


rule APT_Oilrig_Feb18_obfuscation : Feb16_Oilrig_XLS_OR_DOC
{
    meta:
        author = "HONKONE"
        description = "Oilrig new phishing XLS"
        date = "2018-11-19"
    strings:
        $FileName_1 = "C:\\ProgramData\\WindowsAppPool\\AppPool.ps1" nocase ascii
        $FileName_2 = "C:\\ProgramData\\WindowsAppPool\\AppPool.vbs" nocase ascii
    condition:
        all of ($FileName_*)
}
