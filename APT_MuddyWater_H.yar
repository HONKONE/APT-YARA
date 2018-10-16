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
      $path5 = "C:\\Users\\poopak\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path6 = "C:\\Users\\leo\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path7 = "C:\\Users\\Vendetta\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
      $path8 = "C:\\Users\\Turk\\AppData\\Local\\Temp\\Word8.0\\MSForms.exd" ascii
   condition:
      uint16(0) == 0xcfd0 and (1 of ($path*))
}

