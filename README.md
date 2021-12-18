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
3. Reboot remote computer (Single or batch)
4. Service management
5. SCCM remoting management
6. Disable/Enable UAC
7. Enable/Diable firewall
8. Check current logon users
9. User profile management
10. Computer software/hardware information retrieval, including all connected monitors.
11. Task management
12. Uninstall software (Only works for MSI packages)
13. Open cmd/Powershell window with SYSTEM account
14. BSOD analysis, tells you which kernel module causes it.
15. AD user/computer object properties retrieval, BitLocker recovery key retrieval.
16. Local admin management/RDP user management
17. Remotely start a program on the target/push a script (bat/ps1) to the target and run.
18. Clear event logs
19. Windows Update
20. Network scanner ( A similar implementation of PSScanner )
21. Task scheduler
22. Dell BIOS remote management
23. HP BIOS remote management
24. Windows product key retrieval.
25. Old-school terminal style GUI with Runspace multi-threading.
26. Icons are embedded into the script with base64 encoding.
27. Remote with your choice of the current user or specified credential.

Dependencies:
1. Windows SysInternals Suite by Mark Russinovich
2. System-Explorer-for-Windows by Trevor Jones
3. PSParallel Module for multi-threading
4. PSWindowsUpdate module for more flexible control
5. Invoke-CommandAs Module
6. ActiveDirectory Module for all AD queries
7. HP-CMSL for HP BIOS remote management
8. Dell Command | Powershell Provider for Dell BIOS remote management
9. Nirsoft Blue Screen View (https://www.nirsoft.net/utils/bluescreenview.zip)

Screenshots:
![image](https://user-images.githubusercontent.com/57880343/146629267-357d1b97-79f7-4ce0-99a3-e4a1d4302f6b.png)
![image](https://user-images.githubusercontent.com/57880343/146629324-ca1481d6-82d3-409f-825e-6015a4aebe94.png)
![image](https://user-images.githubusercontent.com/57880343/146629479-b8702dc0-1df6-4735-9dc9-dd61cb694902.png)
![image](https://user-images.githubusercontent.com/57880343/146629547-a5ffd92a-5262-42c6-a3de-1f56fc877430.png)
![image](https://user-images.githubusercontent.com/57880343/146629593-fda5aef0-27e2-48d3-aaf0-2498844f9d63.png)

---------------
![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
