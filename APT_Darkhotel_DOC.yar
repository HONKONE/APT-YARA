/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-09-15
   Identifier: Darkhotel

*/
private rule DOC_CVE_2012_0158{
    meta:
        description="Darkhotel hack tool use CVE-2012-0158 in DOC not in RTF"

    strings:
        $a = "3832D640-CF90-11CF-8E43-00A0C911005A"
        $b = "000209F2-0000-0000-C000-000000000046"
        $doc_header = {d0 cf}
        $c = "MSComctlLib.Toolbar.2"

    condition:
        all of them
}

import "pe"

rule APT_Darkhotel_PE_Konni_Oct10
{
    meta:
        description = "Konni_variants"

    strings:
        $s0 = { 78 7A 78 7A 78 7A }
        $s1 = "virus-dl.dll" fullword wide
        $s2 = "Workstation Service Client DLL" fullword wide
        $s3 = "id=%s&time=%s&title=%s %s&passwd=%s" fullword ascii
        $s4 = "This computer's IP Address is%s " fullword ascii
        $s5 = "This computer's username is %s" fullword ascii
        $s6 = "This computer's name is %s" fullword ascii
        $s7 = "%s%s%s\\*" fullword ascii
        $s8 = "%s\\sulted.ocx" fullword ascii
        $s9 = "%s\\tedsul.ocx" fullword ascii
        $s10 = "%s\\trepsl.ocx" fullword ascii
        $s11 = "%s\\psltred.ocx" fullword ascii
        $pdb1 = "F:\\0_work\\planes\\" ascii
                             
    condition:
        ( uint16(0) == 0x5a4d and filesize < 800KB and ( 3 of ($s*) ) ) or ( ($pdb1))
}