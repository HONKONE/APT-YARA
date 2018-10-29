/*
   Yara Rule Set
   Author: HONKONE
   Date: 2018-10-25
   Identifier: APT 12 Japanese Incident
   Reference: httphttps://threatvector.cylance.com/en_us/home/whack-a-mole-the-impact-of-threat-intelligence-on-adversaries.html
*/

/* Rule Set ----------------------------------------------------------------- */

import "pe"

rule APT_StrongPoty_PE_Oct25 {
   meta:
      description = "Detects APT StringPity Malware"
      Author = "HONKONE"
      hash = "737a05b8de40898daaee238508b46bb8"
      /*this decrypt key is use to decrypt PE from resource, but different sample have different decrypt code, this one just for this hash: 737a05b8de40898daaee238508b46bb8*/
      decode_key = "{B3 6E B1 75 67 BD 71 F3 86 CA 7C 95 EC A4 1E 6A 5E 2E 53 65 15 F7 B2 CB 85 4A E3 24 9E F8 34 72 3D CD 32 88 AD 23 59 F2 50 5F 7E 20 9B 79 ED 87 14 DE}"
   strings:
      $powershell = "powershell.exe Set-MpPreference -ExclusionPath 'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64', '%s' -MAPSReporting 0 -DisableBehaviorMonitoring 1 -SubmitSamplesConsent 2" wide ascii
      $func1 = "GetTempPathA" ascii wide nocase
      $func2 = "WaitForSingleObject" ascii wide nocase
      $droper_exe1 = "\\\\netplviz.exe"
      $droper_exe2 = "\\\\evntwn32.xml"
      $droper_exe3 = "\\\\IpOve32.exe"


   condition:
      uint16(0) == 0x5a4d and all of ($droper_exe*) and all of ($func*) and $powershell
}
