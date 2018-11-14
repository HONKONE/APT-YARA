rule APT_APT32_PS_Nov5 : 
{
    meta:
        author = "HONKONE"
        description = "new APT32 sample ,is hta file ,but have same technology of CopyKitty"
        date = "2018-11-05"
    strings:
        $fuc_en1 = {68 6E 65 74 00 68 77 69 6E 69} /*winnet*/
        $fuc_en2 = {4C 77 26 07} /*LoadLibraryExA*/
        $fuc_en3 = {3A 56 79 A7} /*InternetOpenUrlA*/
        $fuc_en4 = {57 89 9F C6} /*InternetConnectW*/
        $fuc_en5 = {EB 55 2E 3B} /*HttpOpenRequestW*/
        
    condition:
        $str or $bytes
}
