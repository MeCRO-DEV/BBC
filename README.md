# BBC (Busy Bee Console)
![bbc](https://user-images.githubusercontent.com/57880343/144734094-ded457c6-3f07-4dd9-b5f1-012e3d3d9d5f.png)
============================================================================
Busy Bee Console is a great tool for IT guy's daily life.
It is dedicated for IT field technicians to perform remote troubleshooting in an enterprise domain environment. It's made for people who has zero knowledge of Powershell and still want to enjoy the power of powershell.
BBC is a WPF application coded in Powershell and XAML. WinRM, network sharing and RPC need to be running on remote computers. You need a domain admin account to run this program.

Contributions : Pull requests and/or suggestions are more than welcome.

Main Features:

Note: Most of the features are supposed to run against the target, a remote computer identified by a host name or IP address.

1. Enable PSRemoting and test the connection
2. Check pending reboot
3. Reboot remote computer
4. Service management
5. SCCM remoting
6. Disable/Enable UAC
7. Enable/Diable firewall
8. Check current logon users
9. User profile management
10. Computer software/hardware information retrieval, including all connected monitors.
11. Task management
12. Uninstall software
13. Open cmd/Powershell window with SYSTEM account
14. BSOD analysis, tells you which kernel module causes it.
15. AD user/computer object properties retreival, BitLocker recovery key retrieval.
16. Local admin management/RDP user management
17. Remotely start a program on the target/push a script (bat/ps1) to the target and run.
18. Clear event logs
19. VBE decoder
20. Network scanner ( A similar implementation of PSScanner )
21. Dell BIOS remote management
22. HP BIOS remote management
23. Windows product key retreival.
24. Old-school terminal style GUI with Runspace multi-threading.
25. Icons are embedded into the script with base64 encoding.
26. Remote with your choice of the current user or specified credential.

Dependencies:
1. Windows SysInternals Suite by Mark Russinovich
2. System-Explorer-for-Windows by Trevor Jones
3. PSParallel Module for multi-threading
4. Invoke-CommandAs Module
5. ActiveDirectory Module for all AD queries
6. HP-CMSL for HP BIOS remote management
7. Dell Command | Powershell Provider for Dell BIOS remote management
8. Nirsoft Blue Screen View (https://www.nirsoft.net/utils/bluescreenview.zip)

Screenshots:
![Capture](https://user-images.githubusercontent.com/57880343/144735774-dc52d22f-692b-47d7-b386-8ca3de1e94c3.PNG)

---------------
![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
