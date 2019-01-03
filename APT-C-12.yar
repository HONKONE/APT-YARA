rule APT_C_12_Sep5_2018
{
    meta:
        author = "HONKONE"
        description = "the lnk file for APT-C-12 which used powershell to download RAT and executed it"
        date = "2019-01-03"
    strings:
        $str1 = "WindowsPowerShell" nocase ascii
        $str2 = "poWERshElL.exe" nocase ascii
        $str3 = "powershell.exe" nocase ascii wide
        $str4 = "%SystemRoot%\\System32\\shell32.dll" nocase ascii
    condition:
      uint16(0) == 0x004C and all of ($str*) and filesize > 500KB
}
