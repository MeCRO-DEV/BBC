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
7. Enable/Diable firewall (3 different ways)
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
25. Local users and groups management
26. Old-school terminal style GUI with Runspace multi-threading.
27. Icons are embedded into the script with base64 encoding.
28. Remote with your choice of the current user or specified credential.

<UL>The best way to utilize multi-threading in Powershell WPF application:</UL>

This is a typical producer-consumer multi-threading model. Every time when the main thread generates a task, it creats a thread from thread pool(in Powershell, we call it RunspacePool). Each thread then generates data and sends it to a concurrent queue, which is a thread safe class implemented in .Net platform. Public variables are stored in a synchronized hash table and protected by mutex. Here is the data flow diagram:

![image](https://user-images.githubusercontent.com/57880343/147320742-a74e9ec7-6131-464c-8cae-26bb0d4bf6d3.png)

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
![image](https://user-images.githubusercontent.com/57880343/147308510-e490ad56-1cea-4260-95a6-492ddb344725.png)
![image](https://user-images.githubusercontent.com/57880343/147308573-323579f9-4313-4ac2-a2b8-b8de8ca793b7.png)
![image](https://user-images.githubusercontent.com/57880343/147308991-c052e11b-0ab4-42de-bff6-5f41173d1ad4.png)
![image](https://user-images.githubusercontent.com/57880343/147309085-c9830edd-bdf0-475f-804e-fb834f555055.png)
![image](https://user-images.githubusercontent.com/57880343/147309179-d9131bec-1e51-4ea7-9f3f-63962634c4f1.png)
![image](https://user-images.githubusercontent.com/57880343/147309308-0e1719ac-f0d0-40ab-987a-2929f373a373.png)
![image](https://user-images.githubusercontent.com/57880343/147309535-77ea062b-dddd-4ecc-9b67-029e67707dee.png)
![image](https://user-images.githubusercontent.com/57880343/147309763-47279efd-23f2-4652-a16c-bce47cc62f58.png)
![image](https://user-images.githubusercontent.com/57880343/147309906-2e1cce7b-a379-4fca-8a92-de84944cd058.png)
![image](https://user-images.githubusercontent.com/57880343/147309946-a7d40b61-25a7-4da3-abc7-5fbeede793a2.png)
![image](https://user-images.githubusercontent.com/57880343/147310032-49a6a1a6-3393-48aa-a459-f6f8f23fc85b.png)

---------------
![](https://komarev.com/ghpvc/?username=MeCRO-DEV&color=green)
