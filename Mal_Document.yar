import "pe"

private rule Document_Header: Private_rule
{
    meta:
        author = "HONKONE"
        description = "use to complate document"
    strings:
        $doc = {D0 CF 11 E0 A1 B1 1A E1}
        $docx = {50 4B 03 04 14 00 06 00}
    condition:
        $doc in (0..10) or $docx in (0..10)
}




rule Mal_Document_Through_VBA_DoMalwareOpt
{
    meta:
        author = "HONKONE"
        description = "how to find mal document from the huge number sample"
    strings:
        $VBaFunc_1 = "AutoOpen" nocase ascii
        $VBaFunc_2 = "AutoClose" nocase ascii
        $VBaFunc_3 = "Document_Open" nocase ascii
        $VBaFunc_4 = "Document_Close" nocase ascii
        $MalVba_1 = "iex" nocase ascii
        $MalVba_2 = "powershell" nocase ascii
        $MalVba_3 = "[char]" nocase ascii
        $MalVba_4 = "' + '" nocase ascii
        $MalVba_5 = /$[\d\w\_]+/ nocase ascii
        $MalVba_6 = "cmd.exe" nocase ascii 
        $MalVba_7 = /%[\w\d]+%/ nocase ascii

    condition:
        1 of ($VBaFunc_*) and 2 of ($MalVba_*) and Document_Header
}
