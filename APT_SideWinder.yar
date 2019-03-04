rule APT_SideWinder_Feb27_RTF
{
    meta:
        author = "HONKONE"
        description = "Suspected APT attack organizations from India continue to attacks against military targets in South Asian countries such as Pakistan"
        reference = "https://twitter.com/HONKONE_K/status/1102414056990814208"
        date = "2019-03-04"
    strings:
        $rtf_header = "{\\rtf"

        $str1 = "6D7368746D6C"  //mshtml
        $str2 = "52756E48544D4C4170706C69636174696F6E" //RunHTMLApplication
        $str3 = "476574436F6D6D616E644C696E6557" //GetCommandLineW
        $str4 = "6E657450726F6341646472657373" //netProcAddress
        $str5 = "616F61644C69627261727957" //aoadLibraryW

        $execute_str1 = "57696E45786563" //WinExec
        $execute_str2 = "5368656C6C4578656375746541" //ShellExecuteA
        $execute_str3 = "63616C6C65722E657865" //caller.exe 
        $execute_str4 = "6200650072006E0065006C00330032"

        $url1 = "7073767677603C776A77327A666662283D3D7176" //encrypted string
        $url2 = "66622D646E2E6E6574" //fb-dn.net
        $url3 = "73322E63646E2D656467652E6E6574" //s2.cdn-edge.net
        $url4 = "7777772E676F6F676C652E636F6D2E642D646E732E636F" //www.google.com.d-dns.co
        $url5 = "6D7366747570646174652E7372762D63646E2E636F6D" //msftupdate.srv-cdn.com
        $url6 = "7777772E6E616472612E676F762E706B2E642D646E732E636F" //www.nadra.gov.pk.d-dns.co
        $url7 = "776562736572762D72656469722E6E6574" //webserv-redir.net
        $url8 = "706D6F2E63646E2D6C6F61642E6E6574" //pmo.cdn-load.net
        $url9 = "73703C776A77327A66666228"
    condition:
        $rtf_header and 3 of ($str*) and 1 of ($execute_str*) and 1 of ($url*)
}
