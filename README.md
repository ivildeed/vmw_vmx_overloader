# vmw_vmx_overloader


Loading unsigned code into kernel of latest Windows 10 (64) with help of VMware Workstation Pro/Player design flaw. 


It is well known, however in case you are not familiar - few words about workstation “hypervisor”:

It is located inside vmware-vmx.exe resources as elf executables.
Those elf’s from usermode resources are manually loaded into kernelmode using helper driver vmx86.sys.
Vmware-vmx.exe and vmx86.sys communication is performed using deviceiocontrols.
One of those controls is VMX86_RUN_VM, it is executed from “vmware-vmx:VMLoader”, vmx86.sys handler for this iocontrol invokes in kernelmode not verified functions delivered from usermode.

So by simply overwriting one function (Host64ToVmm) it is possible to execute our code in kernelmode. 

(after quick check it seems that hypervisor for workstation family is loaded in the same way on macOS and linux)

(.text:0000000140007523 FF D2 call rdx)
When this call is made environment is already partially set for hypervisor creating some limitations, to bypass it in PoC there is upper function return address redirected - making payload execution much more comfortable.


For admin user injecting code to vmware-vmx.exe is as simple as: OpenProcess, VirtualAllocEx, WriteProcessMemory, CreateRemoteThread (w/o elevation)


bonus:
For limited (standard) user it isn't so easy because when vmware-authd service creates vmware-vmx process it sets higher integrity level.
vmware-vmx process uses SetDefaultDllDirectories, SetSearchPathMode and SetDllDirectoryW mitigating simple dll hijacking.
However vmware-authd doesn't sanitize local environment variables when creating child vmware-vmx process, it is possible to set local variable SystemRoot pointing to controlled directory. As it turns out some of dlls dependencies will be loaded from that controlled directory (mswsock.dll is used in PoC)


VMware was contacted regarding this, as a result issues was addressed in security advisory: VMSA-2017-0003 (CVE-2017-4898) 



x64 PoC testing environment:
- i7 2xxx, Windows 10 x64 (1607) HOME, VMware Workstation Full 12.5.2, VMware Workstation Player 12.5.1
- i5 6xxxU, Windows 10 x64 (insider 15002, 15025) PRO, VMware Workstation Full 12.5.2, VMware Workstation Player 12.5.1

binary:
Please keep in mind it is messy barely tested PoC so on other configuration it can potentially cause bsod, system instability or even bricking limited user account. So I don't take responsibility for any damage. You should only use it if you really know what you are doing.


*it is fast and messy PoC, therefore I've used hooks inside vmware-vmx, with proper execution chain and thread context - instead of building malicious request myself

**Quite Frankly I do understand VMware Workstation design - simply it was designed years before Microsoft thought of signing drivers. Interesting now is that MS signed that driver as since Windows 10 (1607) (fresh installations with secureboot) drivers needs to be also signed by Microsoft (Dev Portal). 
Microsoft made that change to make OS supposedly more secure, when vmx86.sys loads to kernelmode code that isn't anyway validated IMO this whole security model goes out of the window(s) ;)
 
