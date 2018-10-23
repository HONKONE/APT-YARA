/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-10-10
   Identifier: MuddyWater samples
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_MuddyWater_Doc_Oct10 {
   meta:
      description = "Detects malicious document used by MuddyWater and use Powershell"
      license = "https://securelist.com/muddywater/88059/"
      author = "HONKONE"
      date = "2018-10-10"
   strings:
      /* iex([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String( */
      $path1 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii wide
      $path2 = "C:\\Users\\leo\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii wide
      $path3 = "C:\\Users\\Vendetta\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii wide
      $path4 = "C:\\Users\\Turk\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii wide
      $path5 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path6 = "C:\\Users\\leo\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path7 = "C:\\Users\\Vendetta\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path8 = "C:\\Users\\Turk\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
   condition:
      uint16(0) == 0xcfd0 and (1 of ($path*))
}

/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-10-17
   Identifier: MuddyWater samples
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_MuddyWater_Doc_Oct10_17_1 {
   meta:
      description = "Detects malicious document used by MuddyWater and use to download exp from github"
      license = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/"
      author = "HONKONE"
      hash = "c90e22b6579a3447836e299cbc5d0af0"
      date = "2018-10-17"
   strings:
      $path1 = "C:\\PROGRA~2\\COMMON~1\\MICROS~1\\VBA\\VBA7.1\\VBE7.DLL" wide ascii
      $id1 = "C:\\Users\\NEO\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $id2 = "C:\\Users\\NEO\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" wide ascii
      $tid1 = "rs\\samoe"
      $tid2 = "l\\AppDat"
      $tid3 = "a\\Local\\"
      $oid1 = "Users\\GI"
      $oid2 = "GABYTE\\A"
      $oid3 = "ppData\\L"
      $code1 = "VBComponents"
      $code2 = "Base64DecodeString"
      $code3 = "Execute"
      $code4 = "Net.WebRequest"
      $arg1 = "noo"
   condition:
      uint16(0) == 0xcfd0 and (all of ($code*)) and $arg1 and $path1 or (1 of ($id*)) or (all of ($tid*)) or (all of ($oid*))
}

rule APT_MuddyWater_Doc_Oct10_17_2 {
   meta:
      description = "Detects malicious document used by MuddyWater and use to download exp from github"
      license = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/"
      author = "HONKONE"
      date = "2018-10-17"
   strings:
      $code1 = "root\\default:StdRegProv"
      $code2 = "winmgmts:{impersonationLevel=impersonate}"
      $protect = /DPB="[\d\w]+"/
   condition:
      uint16(0) == 0xcfd0 and all of ($code*) and $protect
}

rule APT_MuddyWater_Doc_Oct10_17_3 {
   meta:
      description = "Detects malicious document used by MuddyWater and use to download exp from github"
      license = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/"
      author = "HONKONE"
      date = "2018-10-17"
   strings:
      $Tcode1 = "Select * from Win32_Processor"
      $Acode2 = "tcpview"
      $Acode3 = "wireshark"
      $Acode4 = "process explorer"
      $Acode5 = "visual basic"
      $code2 = "ell.exe -Windo"
      $code3 = "wStyle hid"
      $code4 = "den -Executio"
      $code5 = "nPolicy Byp"
      $code6 = "ass -nologo -no"
      $code7 = "profile -e"
      $str = "Microsoft Word"
   condition:
      uint16(0) == 0xcfd0 and $str and ((all of ($code*)) or ($Tcode1 and 1 of ($Acode*)))
}

/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-10-17
   Identifier: MuddyWater samples
*/

/* Rule Set ----------------------------------------------------------------- */

rule APT_MuddyWater_Xls_Oct10_17 {
   meta:
      description = "Detects malicious document used by MuddyWater and use to download exp from github"
      license = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/"
      author = "HONKONE"
      date = "2018-10-17"
   strings:
      $str1 = "???"
      $str2 = ";_(@_)  }"
      $str3 = "00\\);_(*"
      $func1 = "\\root\\cimv2:Win32_Process"
      $func2 = "powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -e "
      $str = "Microsoft Excel"
   condition:
      uint16(0) == 0xcfd0 and ((#str1 > 10 and #str2 > 30 and #str3 > 60) and (all of ($func*))) and $str
}

rule APT_MaybeMuddyWater_PS2EXE_Oct10_17 {
   meta:
      description = "Detects malicious document used by MuddyWater and execute by PS2EXE"
      license = "https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/"
      author = "HONKONE"
      date = "2018-10-17"
   strings:
      $str1 = "PS2EXE" wide ascii
      $code1 = "KeyAvailable/Get" wide ascii
   condition:
      uint16(0) == 0x5A4D and $str1 and $code1
}




