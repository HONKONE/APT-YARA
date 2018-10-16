/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-10-10
   Identifier: MuddyWater samples
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_MuddyWater_Doc_Oct10_1 {
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
      $haxpath = {43  3A  5C  55  73  65  72  73  5C  70  6F  6F  70
                  61  6B  5C  41  70  70  44  61  74  61  5C  4C  6F  63  61  6C  5C  54  65  6D  70
                  5C  57  6F  72  64  38  2E  30  5C  4D  53  46  6F  72  6D  73  2E  65  78  64}
   condition:
      uint16(0) == 0xcfd0 and (1 of ($path*) or $haxpath)
}

