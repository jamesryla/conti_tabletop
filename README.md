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
The first step in this exercise is to locate the malware within the system. This exercise assumes the attacker already has initial access. Using the [sysmon reference guide](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), we see that Event ID 11 is used for the creation of files. I will search using EventCode=11 and look under the Image category for any standout files. cmd.exe has been created in /Documents which stands out as abnormal.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=11

![ioc1result](https://github.com/jamesryla/conti_tabletop/assets/58945104/161e6eee-c9db-43b0-bbe3-62ea9a25b553)

### 2
We can verify the maliciousness of this file by getting the md5 hash. I will specify the cmd.exe Image from above and search md5 to grab the hash. Heading over to virustotal, we can search using the hash and see that this file is indeed malicious and has been categorized as conti ransomware by various security vendors.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="C:\\Users\\Administrator\\Documents\\cmd.exe" md5

![ioc2result](https://github.com/jamesryla/conti_tabletop/assets/58945104/c6cc6cba-fbf8-4c70-9187-0759bd094ce7)
![ioc2virustotal](https://github.com/jamesryla/conti_tabletop/assets/58945104/856ff9b4-87f9-4ba7-8f91-fb29db4e52c3)

### 3
Ransomware usually comes with some form of ransom note. I will use the same search as above minus the md5 addition and look under the TargetFilename field. We can see the readme.txt's that have been created.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" Image="C:\\Users\\Administrator\\Documents\\cmd.exe"

![ioc3result](https://github.com/jamesryla/conti_tabletop/assets/58945104/ca8857f7-a814-4ab2-b0c7-e065dafd1ca0)
![ioc3readme](https://github.com/jamesryla/conti_tabletop/assets/58945104/7b6a49d3-7dd8-4e4a-86b1-998ce1c66b5b)

### 4
Knowing how to add/edit users on Windows can be helpful in finding other IOC's. By searching the CommandLine field for keywords like "net", "user" & "/add" we can quickly find that the attacker added a new user.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" CommandLine="*/add*"

![ioc4result2](https://github.com/jamesryla/conti_tabletop/assets/58945104/f647b0c7-5980-46ff-a5b4-d53e927376f6)

### 5
Referencing the sysmon guide again, we find that Event ID 8 CreateRemoteThread event detects when a process creates a thread in another process. It states that this technique is used by malware to inject code and hide other processes. Searching using this EventCode and further, looking at the SourceImage category, allows us to see that attacker migrated to powershell for better persistence.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8

![ioc5result](https://github.com/jamesryla/conti_tabletop/assets/58945104/77e4a4ff-fd86-4768-8e9d-30a275eca21e)

### 6
Using the same search as above but looking under the TargetImage category, we can see that the lsass.exe was used to dump the system hashes.
> index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8

![ioc6result](https://github.com/jamesryla/conti_tabletop/assets/58945104/7fd96a15-1a44-44a2-b04b-d3513a0dccd9)

### 7
In this exercise we also have access to IIS (Windows Server) logs. IIS or Internet Information Services logs can provide us with crucial IOC's especially if the attacker used a web shell to gain access to the system. [reference](https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/)
We can search these logs for http POST method and for common web shell file types like php, asp, aspx, py, prl, rb.
> index=main sourcetype=iis cs_method=POST | search *.php* OR *.asp* OR *.aspx* OR *.jsp* OR *.prl* OR *.py* OR *.rb*

![ioc7result](https://github.com/jamesryla/conti_tabletop/assets/58945104/52318fa3-7333-4a5b-ba28-d8ab98f816f6)

### 8
Finally, heading back to our sysmon logs, let's see if we can track down how this shell was executed. We can achieve this by searching for the .aspx file we previously found and checking out the CommandLine field.
> index=main i3gfPctK1c2x.aspx sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational"

![ioc8result](https://github.com/jamesryla/conti_tabletop/assets/58945104/4e3fed10-8819-475f-85ce-aa3142403077)

*references*
- [Original challenge](https://tryhackme.com/room/contiransomwarehgh) via [tryhackme](https://tryhackme.com)
- [Infosec Write-Ups](https://infosecwriteups.com/conti-ransomware-threat-hunting-with-splunk-5dfe72635dbe?gi=c28cea33b960)
- [Sysmon guide](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Microsoft security guide on IIS extensions](https://www.microsoft.com/en-us/security/blog/2022/07/26/malicious-iis-extensions-quietly-open-persistent-backdoors-into-servers/)
- [Crowdstrike guide on IIS logs](https://www.crowdstrike.com/cybersecurity-101/observability/iis-logs/)
- [Conti ransomware IOCs - CISA](https://www.cisa.gov/news-events/alerts/2021/09/22/conti-ransomware)
