# antiPEHsentinel
A python script to harden a Domain Controller against common AD exploits  

This program is designed to be run on a Domain Controller or a Windows Machine with administrator privileges. It will auto-
quite if it detects itself running on a non-windows machine.  

The program requires Python 3.13.3, but there is an .exe version in the dist folder as well.  
  
This program is essentially just a collection of PowerShell scripts that are ran after being selected by the user.  
It's intended purpose is to harden the DC from some of the common vulnerabilities taught in the TCM Security PEH course.  
  
It's intended to be modular in nature so that more functions can be added.  
The functions themselves are simple in nature. As a future project, I may add features  
like being able to disable certain functions directly from the Domain Controller, but  
for now I've decided to keep it all local.

## Options 1 & 2 - LLMNR
These functions check to see if LLMNR is enabled and disable it, respectively.  

## Options 3 & 4 - NetBIOS
These functions check to see if NetBIOS is enabled, and disable it, respectively.  

## Options 5 & 6 - SMBv1
These functions check to see if SMBv1 is enabled, and disable it, respectively. 

## Options 7 & 8 - SMB Signing
These functions check to see if SMB signing is enforced. If it is not, then function 8  
will enforce it.

## Options 9 & 10 - Wdigest
These functions check to see if Wdigest is enabled, and disable it, respectively.  

## Option 11 - Audit NTLM/LmCompatibilityLevel
This function checks to see what level LmCOmpativilityLevel is set to, and returns what  
that means in terms of NTLMv1 and NTLMv2. I have it set so that any value between 0 and 2 is  
no good!  

## Option 12 - Set LmCompatibilityLevel
This function prompts the user to choose a level to set LmCompatibilityLevel to. The only  
options are level 3 through 5. This is for cases where you still have devices on your system  
that require NTLMv1. In the future, I want to add a featur that parses through the NTLM log  
to find and list devices that still fall back on NTLMv1.

## Option 13 - Audit ADCS Default Templates
This function tells you whether or not ADCS is running two default templates, ENROLL or ESC1-4. It will tell you if you have one, the other, or both.  

## Option 14 - Remove ENROLL and ESC1-4 Templates from ADCS
This function removes ENROLL and ESC1-4 to harden the Domain Controller from certificate  
impersonation attacks. Templates can later be added manually. 

## Option 15 - List SPNs with Priviliged Access
This function searches for service accounts that are part of privileged AD groups. It doesn't alter the accounts or their privileges. In the future I'd like to add features where the user can select which particular groups to remove the service accounts from. 


