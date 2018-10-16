/*
    Author: HONKONE
    Date: 2018-10-10
    Description: ZxShell for APT-C-01
*/

import "pe"

private rule is_DLL{
    condition:
        uint16(0) == 0x5A4D and
        uint8(uint32(0x3c)+23) == 0x21
}

rule APT_C01_DLL_ZxShell_Oct10{
	meta:
		description = "ZxShell is a type of RAT for APT-C-01"

	strings:
	   $a = "Richnt"
	   $b = "2WV"
	   $c = "SYSTEM\\CurrentControlSet\\Control\\zxplug"
	   $d = "zxFunction002: %s"
	   $e = /\[\w[\w\d\s]{2,}\]/
	   $f = "InitZXShellSubtleAPI"

	condition:
	    is_DLL and #e > 30 and all of them
}
