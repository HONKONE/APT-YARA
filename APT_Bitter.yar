rule APT_Bitter_RTF_01:RTF OR DOCX
{
	meta:
		author = "HONKONE"
		md51 = "0F1E75A70FC90ADCA17710F7D65F205B"
		md52 = "3D163CC7329ED049D3E32B5D11586236"
		md53 = "4E09AA10E8F0C40E74733A9345695D84"
		md54 = "981DEB00AAC4F6EBE9ACEB401DEDE6F3"
		md55 = "68907B9AB744C9D9CAE4C27E0B82EB4A"
		md56 = "E152B5B7E9079F689EBAAA9B8FE2ED66"
		md57 = "CEE5AF57AC60B023F2C715388E34F6DB"
		md58 = "E39629316B4BF049FC9704DD00E41B6A"
		md59 = "B5D73517BB02545E8776DB4C8A66B62A"
	strings:
		$domain1 = "62617A61726172656E612E636F6D" nocase
		$domain2 = "7363686F6C61727339302E77656273697465" nocase
		$domain3 = "7A6D77617264726F62652E636F6D" nocase
		$domain4 = "686172747261646572732E636F6D" nocase
		$domain5 = "7363686F6C61727339302E77656273697465" nocase
		$domain6 = /63[\n\r]{0,}7265656439302E636F6D/ nocase
		/*
		creed90.com
		scholars90.website
		hartraders.com
		scholars90.website
		http://bazararena.com/mlr
		zmwardrobe.com
		*/
		$func1 = "4D6F766546696C6541" nocase
		$func2 = "6F70656E" nocase
		$func3 = "5368656C6C4578656375746541" nocase
		$func4 = /55524C446F776E6C6F6164546F46[\n\r]{0,}696C6541/ nocase
		$func5 = "57696E457865" nocase
		$func6 = "57696E45786563" nocase 
		$func7 = "6D6F7665" nocase
		/*
		$pe_name1 = "637376742E657865" nocase
		$pe_name2 = "696766782E657865" nocase
		$pe_name3 = "636E682E657865" nocase
		$pe_name4 = "637376782E657865" nocase
		$pe_name5 = "73706C7372762E657865" nocase
		"636F6E686F73742E657865"
		*/

	condition:
		1 of ($domain*) and (2 of ($func*))
}


rule APT_Bitter_Downloader_PE_01 : Bitter Downloader
{
    meta:
        author = "HONKONE"
        description = "Bitter Downloader"
        
    strings:
        $PE_header = "!This program cannot be run in DOS mode." wide ascii 
        $func1 = "ExitProcess" wide ascii
        $func2 = "GetProcess" wide ascii
        $func3 = "FreeEnvironmentStringsW" wide ascii
        $func4 = "GetTickCount" wide ascii
        $func5 = "WriteConsoleW" wide ascii
        $func6 = "LoadLibraryA" wide ascii
        $load_dll_1 = "mscoree.dll" wide ascii 
        $load_dll_2 = "KERNEL32.DLL" wide ascii 
        $load_dll_3 = "USER32.DLL" wide ascii 
        $load_dll_4 = "WS2_32.dll" wide ascii 
        $pdb1 = "C:\\Users\\UserA\\Documents\\Visual Studio 2008\\Projects\\Artra\\Release\\Artra.pdb" wide nocase ascii
    	$pdb2 = "C:\\Users\\ULTRON\\Documents\\Visual Studio 2008\\Projects\\Down02Sept\\Release\\Down02Sept.pdb" wide nocase ascii
    	$pdb3 = "C:\\Users\\INFINITE\\Documents\\Visual Studio 2008\\Projects\\NewDown\\Release\\NewDown.pdb" wide nocase ascii
    	$pdb4 = "C:\\Users\\UserA\\Documents\\Visual Studio 2008\\Projects\\Artra\\Release\\Artra.pdb" wide nocase ascii
    	$pdb5 = "C:\\poke\\Release\\poke.pdb" wide nocase ascii
    	$pdb6 = "C:\\Users\\ARAGON\\Documents\\Visual Studio 2008\\Projects\\DownWin32\\Release\\DownWin32.pdb" wide nocase ascii
    	$pdb7 = "C:\\Users\\INFINITE\\Documents\\Visual Studio 2008\\Projects\\DownWin32\\Release\\DownWin32.pdb" wide nocase ascii
    	$pdb8 = "C:\\Users\\ULTRON\\Documents\\Visual Studio 2008\\Projects\\Down02Sept\\Release\\Down02Sept.pdb" wide nocase ascii
    	$pdb9 = "C:\\Users\\ANONYMOUS\\Documents\\Visual Studio 2008\\Projects\\Down Free\\DownWin32\\Release\\DownWin32.pdb" wide nocase ascii
    	$pdb10 = "C:\\medal\\Release\\medal.pdb" wide nocase ascii
    	$pdb11 = "C:\\iexpo\\Release\\iexpo.pdb" wide nocase ascii
    	$pdb12 = "E:\\RATFUD\\dllhost\\Release\\dllhost.pdb" wide nocase ascii
    	$pdb13 = "C:\\Users\\pc5\\Documents\\Visual Studio 2008\\Projects\\WMIS\\Release\\WMIS.pdb" wide nocase ascii
    	$pdb14 = "D:\\MyWork\\VisualSudio\\mwow\\Debug\\mwow.pdb" wide nocase ascii
    	$pdb15 = "c:\\Users\\Dexter\\Documents\\Visual Studio 2008\\Projects\\1\\Release\\1_3.pdb" wide nocase ascii
    condition:
        $PE_header and 3 of ($func*) and all of ($load_dll*) and 1 of ($pdb*)
}


rule APT_Bitter_Jan4: Bitter RTF Downloader
{
    meta:
        author = "HONKONE"
        description = "new rtf downloader for bitter"
        date = "2019-01-04"
    strings:
        $rtf_hedaer = "{\\rt"
        $str = /6A6B6C613A2F2F[\d\w]+/ ascii nocase
        $func1 = "4372656174654469726563746F727941" nocase ascii
        $func2 = "4C6F61644C69627261727941" nocase ascii
        $func3 = "75726C6D6F6E2E646C6C" nocase ascii
        $func4 = "6F776E6C6F6164546F46696C6541" nocase ascii
        $func5 = "4D6F766546696C6541" nocase ascii
        $func6 = "5368656C6C33322E646C6C" nocase ascii
        $func7 = "5368656C6C4578656375746541" nocase ascii
        $func8 = "6F70656E" nocase ascii
    condition:
        $str and $rtf_hedaer and all of ($func*)	
}


rule APT_Bitter_Jan4_RAR2EXE : Bitter RAR2EXE
{
    meta:
        author = "HONKONE"
        description = "RAR2EXE"
        date = "2019-01-04"
    strings:
        $str1 = "CMT;The comment below contains SFX script commands" nocase ascii wide
        $str2 = "Path" nocase ascii
        $str3 = /Setup=[\"\d\w\s]+\.[doc|docx|rtf]\"{0,1}/ nocase ascii
        $str4 = "Silent" nocase ascii
        $str5 = "Overwrite" nocase ascii
    condition:
        uint16(0) == 0x5A4D and all of ($str*)
}
