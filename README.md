# conti_tabletop

## Using Splunk with Sysmon &amp; IIS logs to track Conti Ransomware. A practice tabletop exercise for learning to better utilize Splunk.

This challenge originally comes from tryhackme and is an exercise is finding evidence of an attackers' movement within Sysmon & Windows server logs.

This writeup/tabletop is an attempt to further understand splunk searching & the IOCs of Conti.

### Exercise Scenario
- employees begin experiencing issues logging into Microsoft Outlook.
- exchange system admin cannot log into exchange admin center
- readme file found on exchange server - common conti ransomware message about encrypted data
![outlook_web_access](https://github.com/jamesryla/conti_tabletop/assets/58945104/0f694fe7-08a5-4268-9cf6-b28d451fe107)
![exchange_control_panel](https://github.com/jamesryla/conti_tabletop/assets/58945104/1c01aef2-e5a7-4210-8302-c4f2b27387ad)

### 1
The first step should be to locate the malware within the system. This exercise assumes the attacker already has initial access. Using the [sysmon reference guide](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), we see that Event ID 11 is used for the creation of files. I will search using EventCode=11 and look under the Image category for any standout files. cmd.exe has been created in /Documents which immediately stands out as abnormal.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11

![ioc1result](https://github.com/jamesryla/conti_tabletop/assets/58945104/161e6eee-c9db-43b0-bbe3-62ea9a25b553)

*references*
- [Original challenge](https://tryhackme.com/room/contiransomwarehgh) via [tryhackme](https://tryhackme.com)
- [Infosec Write-Ups](https://infosecwriteups.com/conti-ransomware-threat-hunting-with-splunk-5dfe72635dbe?gi=c28cea33b960)
- [Sysmon guide](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft security guide on IIS extensions](https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/)
- [Crowdstrike guide on IIS logs](https://www.crowdstrike.com/cybersecurity-101/observability/iis-logs/)
- [Conti ransomware IOCs - CISA](https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware)
