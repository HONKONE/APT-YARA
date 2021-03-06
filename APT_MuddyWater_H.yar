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


rule MuddyWater_doc_dropper {
	meta:
		description = "Yara Rule for MuddyWater document dropper"
		author = "Yoroi ZLab - Cybaze"
		last_updated = "2018-12-05"
		tlp = "white"
		category = "informational"
	strings:
		$header ={D0 CF 11 E0 A1 B1 1A E1}
		$a = {D3 60 25 12 C4 C1 41 B1 65 E3 39 08 8B}
		$b = {B1 B8 22 60 2B 2E 62 59 58 11}
	condition:
		 all of them
}

rule MuddyWater_fake_pgn_dropper {
	meta:
		description = "Yara Rule for MuddyWater fake image dropper"
		author = "Yoroi ZLab - Cybaze"
		last_updated = "2018-12-05"
		tlp = "white"
		category = "informational"
	strings:
		$a = "I0B+XlhBQUFBQT09L00rQ0QrfTRMf21EY0pxL15EYndPIFV0K15zSipSSSFVfkoxL"
		$b = "1mdW5jdGlvbihzLGQpe3ZhciB1PVtdLHY9MHgwLHcseD0nJyx5PScn"
	condition:
		 all of them
}

rule MuddyWater_encrypted_POWERSTATS {
	meta:
		description = "Yara Rule for MuddyWater encrypted backdoor"
		author = "Yoroi ZLab - Cybaze"
		last_updated = "2018-12-05"
		tlp = "white"
		category = "informational"
	strings:
		$a = "256/8Z2S63F,17P1P?20N,-(1AR38(.E/,Y7/VB->V0E,.1J1L*0?H-"
		$b = "0E-13./)F/[-/L)/.I-*U/.F/*@3AM37M2?T-=I3-J/BU-=?/GP,JN1Z<05I-)V/C-"
	condition:
		 all of them
}

