# proxynotshell-IOC-Checker

Powershell script used to check for IOC's based on community research and those provided by Microsoft:
* [GTESC](https://gteltsc.vn/blog/warning-new-attack-campaign-utilized-a-new-0day-rce-vulnerability-on-microsoft-exchange-server-12715.html)
* [The Sec Master](https://thesecmaster.com/how-to-mitigate-cve-2022-41040-a-0-day-ssrf-vulnerability-in-microsoft-exchange-server/)
* [Double Puslar](https://doublepulsar.com/proxynotshell-the-story-of-the-claimed-zero-day-in-microsoft-exchange-5c63d963a9e9)
* [Microsoft Security Resource Center](https://msrc-blog.microsoft.com/2022/09/29/customer-guidance-for-reported-zero-day-vulnerabilities-in-microsoft-exchange-server/)
* [Microsoft Security Blog](https://www.microsoft.com/security/blog/2022/09/30/analyzing-attacks-using-the-exchange-vulnerabilities-cve-2022-41040-and-cve-2022-41082/)

The script may be updated to include more IOC's as more information is made available.


## :arrow_down: Download
```
git clone https://github.com/rjsudlow/proxynotshell-IOC-Checker
```


## :rocket: Usage
Run the following command in an elevated PS shell from the affected server:
```
.\proxynotshell-IOC-Checker.ps1 'Path\to\Logs\'
```
