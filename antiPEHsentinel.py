import subprocess
import platform
import sys
import json

def greeting():
    print("""
   _____    __________________.___            _____________________ ___ ___  
  /  _  \   \      \__    ___/|   |           \______   \_   _____//   |   \ 
 /  /_\  \  /   |   \|    |   |   |   ______   |     ___/|    __)_/    ~    \\         
/    |    \/    |    \    |   |   |  /_____/   |    |    |        \    Y    /
\____|__  /\____|__  /____|   |___|            |____|   /_______  /\___|_  / 
        \/         \/                                           \/       \/  
          """)
    print("\n*****************************************************************************")
    print("\n*                                                                           *")
    print("\n* Disable the exploits taught in the TCM PEH course                         *")
    print("\n*                                                                           *")
    print("\n*                                                                           *")
    print("\n*****************************************************************************")

# Check to make sure the program is running on windoes
def windows_check():
    if platform.system() != "Windows":
        print("\n Error! This program can only be run on Windows!")
        sys.exit(1)

def menu():
    print("""
*****************************************************************************
* 1  - Check if LLMNR is Enabled                                            *
* 2  - Disable LLMNR                                                        *
* 3  - Check if NetBIOS is Enabled                                          *
* 4  - Disable NetBIOS                                                      * 
* 5  - Check if SMBv1 is Enabled                                            *
* 6  - Disable SMBv1                                                        *
* 7  - Check if SMB signing is Enforced                                     *
* 8  - Enable SMB signing Enforcement                                       *
* 9  - Check if Wdigest is Enabled                                          *
* 10 - Disable Wdigest                                                      *
* 11 - Audit NTLM/LmCompatibilityLevel Settings                             *
* 12 - Set LmCompatibility Level                                            *
* 13 - Audit ADCS Default Templates                                         *
* 14 - Remove ENROLL and ESC1-4 Templates from ADCS                         *
* 15 - List SPNs with Privileged Access                                     *
* help - Print Menu                                                         *
* exit - Terminate Program                                                  *
*****************************************************************************
          """)

# 1
# Function to check if LLMNR is enabled
def is_llmnr_enabled():
    try:
        # Powershell script to check the EnableMulticast value and return a code 
        is_llmnr_enabled_script = r'''
        $value = Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction Stop
        if ($value.EnableMulticast -eq 1) { exit 0 } else { exit 1 }
        '''
        result = subprocess.run(["powershell.exe", "-Command", is_llmnr_enabled_script], capture_output=True)
        if result.returncode == 0:
            print("[!] LLMNR is currently ENABLED.")
            return True
        else:
            print("[!] LLMNR is already DISABLED.")
            return False
    except Exception as e:
        print(f"[!] Could not determine LLMNR status: {e}")
        return None

# 2
# Function disables LLMNR poisoning
def disable_llmnr_poisoning():
    print("[*] Disabling LLMNR via registry...")
    try:
        # PowerShell script to modify the value of EnableMulticast to 0 to disable LLMNR
        disable_llmnr_script = r'Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Force'
        subprocess.run(["powershell.exe", "-Command", disable_llmnr_script], check=True)
        print("[-] LLMNR disabled.")
        return True
    except subprocess.CalledProcessError:
        print("[-] Failed to disable LLMNR. Are you running as administrator?")
        return False

# 3
# Function to check if NetBIOS is enabled on a NIC in the network
def is_netbios_enabled():
    try:
        print("[*] Checking NetBIOS status on all interfaces...")
        # PowerShell Script to loop through all NICs and check their NetbiosOptions value
        # 0 = DHCP controlled, 1 = Explicitly enabled, 2 = Disabled
        is_netbios_enabled_script = r'''
        $paths = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        $enabled = $false
        foreach ($path in $paths) {
            $netbios = Get-ItemProperty -Path $path.psPath -Name NetbiosOptions -ErrorAction SilentlyContinue
            if ($netbios.NetbiosOptions -eq 1 -or $netbios.NetbiosOptions -eq 0) {
                $enabled = $true
                }
        }
        if ($enabled) { exit 0 } else { exit 1 }
        '''
        result = subprocess.run(["powershell.exe", "-Command", is_netbios_enabled_script], capture_output=True)
        if result.returncode == 0:
            print("[!] NetBIOS is ENABLED on one or more interfaces.")
            return True
        else:
            print("[+] NetBIOS is DISABLED on all interfaces.")
            return False
    except Exception as e:
        print(f"[!] Error checking NetBIOS status: {e}")
        return None

# 4
# Function to disable NetBIOS
def disable_netbios():
    try:
        print("[*] Disabling NetBIOS...")
        # Powershell script that iterates through all NICs and forces interface value to 2
        disable_netbios_script = r'''
        $paths = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces"
        foreach ($path in $paths) {
            Set-ItemProperty -Path $path.PSPath -Name NetbiosOptions -Value 2 -Force
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", disable_netbios_script], check=True)
        print("[+] NetBIOS disabled on local machine. A reboot may be required for full effect.")
        return True
    except subprocess.CalledProcessError:
        print("[-] Failed to Disable NetBIOS. Are you running as administrator?")
        return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# 5
# Function to check if SMBv1 is enabled
def is_smbv1_enabled():
    try:
        print("[*] Checking if SMBv1 is enabled...")
        # Powershell Script that checks if SMBv1 is enabled on the local machine
        is_smbv1_enabled_script = r'''
        $key = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $smb1 = Get-ItemProperty -Path $key -Name SMB1 -ErrorAction SilentlyContinue
        if ($null -eq $smb1) {
            exit 0
        } elseif ($smb1.SMB1 -eq 1) {
            exit 0
        } else {
            exit 1
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", is_smbv1_enabled_script], capture_output=True)
        if result.returncode == 0:
            print("[!] SMBv1 is ENABLED on this machine.")
            return True
        else:
            print("[+] SMBv1 is DISABLED on this machine.")
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# 6
# Function to disable SMBv1
def disable_smbv1():
        print("[*] Disabling SMBv1...")
        # Powershell script to disable SMBv1 locally and via GPO
        disable_smbv1_script = r'''
        try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Value 0 -Force
        Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction Stop
        Write-Output "[*] SMBv1 disabled successfully. A reboot is recommended for full effect."
        exit 0
        } catch {
        Write-Output "[-] Failed to disable SMBv1: $($_.Exception.Message)"
        exit 1
        }
    '''
        try: 
            result = subprocess.run(["powershell.exe", "-Command", disable_smbv1_script], capture_output=True, text=True)
            if result.returncode == 0:
                print("[+] SMBv1 successfully disabled via GPO and locally.")
                print(result.stdout)
                return True
            else:
                print("[-] Failed to dsiable SMBv1. Are you logged in as administrator?")
                print(result.stdout)
                return False
        except Exception as e:
            print(f"[!] Unexpected error! {e}")
            return None

# 7
# Function to check if SMB signing is enabled
def check_smb_signing():
    try: 
        print("[*] Checking if SMB signing is enforced...")
        # Powershell script to check the value for SMB signing
        check_smb_signing_script = r'''
        $value = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -ErrorAction SilentlyContinue
        if ($value -eq 1) {
            exit 0 
        } else {
            exit 1 
        }
        '''
        smb_check = subprocess.run(["powershell.exe", "-Command", check_smb_signing_script], capture_output=True)
        if smb_check.returncode == 0:
            print("[+] SMB signing is ENFORCED on this machine.")
            return True
        else:
            print("[-] SMB signing is NOT enforced on this machine.")
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# 8
# Function to enforce SMB signing
def enforce_smb_signing():
    try:
        print("[*] Enforcing SMB signing...")
        # PowerShell script that sets SMB signing requirement in the registry
        enforce_smb_signing_script = r'''
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
                             -Name "RequireSecuritySignature" -Value 1 -Force
            Write-Output "[+] SMB signing enforced successfully."
            exit 0
        } catch {
            Write-Output "[-] Failed to enforce SMB signing: $($_.Exception.Message)"
            exit 1
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", enforce_smb_signing_script], capture_output=True, text=True)
        if result.returncode == 0:
            print("[+] SMB signing enforcement enabled.")
            print(result.stdout)
            return True
        else:
            print("[-] Failed to enforce SMB signing. Are you running with administrative privileges?")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# 9
# Function to check if Wdigest is enabled
def check_wdigest():
    try:
        print("[*] Checking if Wdigest is enabled...")
        check_wdigest_script = r'''
        $key = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
        $value = Get-ItemProperty -Path $key -Name "UseLogonCredential" -ErrorAction SilentlyContinue
        if ($value.UseLogonCredential -eq 1) {
            exit 0
        } else {
            exit 1
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", check_wdigest_script], capture_output=True, text=True)
        if result.returncode == 0:
            print("[-] Wdigest is ENABLED.")
            return True
        else:
            print("[+] Wdigest is DISABLED.")
            return False
    except Exception as e:
        print(f"Unexpected error!! {e}") 
        return None

# 10
# Function to disable Wdigest
def disable_wdigest():
    try:
        print("[*] Disabling Wdigest...")
        # PowerShell script that checks if UserLogonCredential exists and then sets it to 0
        disable_wdigest_script = r'''
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "UseLogonCredential" -Value 0 -Force
            exit 0
        } catch {
            Write-Output "[-] Failed to disable Wdigest: $($_.Exception.Message)"
            exit 1
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", disable_wdigest_script], capture_output=True)
        if result.returncode == 0:
            print("[+] Wdigest has been DISABLED")
            return True
        else:
            print("[-] Failed to disable Wdigest. Are you running with administrative privileges?")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")

# 11
# Function to check NTLM settings and LmCompatibilityLevel
def check_ntlm():
    print("[*] Checking NTLM settings...")
    try:
        check_ntlm_script = r'''
        try {
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $lmLevel = Get-ItemPropertyValue -Path $regPath -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
            if ($null -eq $lmLevel) {
                Write-Output "LmCompatibilityLevel not set."
                exit 6
            }
            switch ($lmLevel) {
                0 { exit 0 }
                1 { exit 1 }
                2 { exit 2 }
                3 { exit 3 }
                4 { exit 4 }
                5 { exit 5 }
            }
        } catch {
            Write-Output "[-] Failed to retrieve NTLM settings: $($_.Exception.Message)"
            exit 7
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", check_ntlm_script], capture_output=True, text=True)
        if result.returncode == 0:
            print("[-] NTLM is fully enabled (allows LM and NTLMv1).")
            return False
        elif result.returncode == 1:
            print("[-] NTLM is enabled (refuses LM, allows NTLMv1).")
            return False
        elif result.returncode == 2:
            print("[+] NTLMv2 responses only (refuses LM and NTLMv1).")
            return True
        elif result.returncode == 3:
            print("[+] NTLMv2 responses only, requires NTLMv2 for all clients.")
            return True
        elif result.returncode == 4:
            print("[+] NTLMv2 responses only, refuses LM and NTLMv1, uses NTLMv2 session security.")
            return True
        elif result.returncode == 5:
            print("[+] NTLMv2 only, requires NTLMv2 session security.")
            return True
        elif result.returncode == 6:
            print("[!] NTLM configuration unknown or not set.")
            return None
        elif result.returncode == 7:
            print("[!] Failed to retrieve NTLM settings")
            print(result.stdout)
            return None
        else:
            print("[!] Unexpected return:" + str(result.returncode))
            print(result.stdout)
            return None
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None
    
# 12
# Function to set LmCompabitibilityLevel for NTLM
def set_ntlm_settings():
    try:
        print("[*] Choices:")
        print("[*] Level 3: Block LM, Allow NTLMv1, Don't require NTLMv2 session security.")
        print("[*] Level 4: Block LM and NTLMv1, Only NTLMv2 responses allowed, Don't enforce session security.")
        print("[*] Level 5: Block LM and NTLMv1, Only NTLMv2 responses allowed, requires session security (most secure option)")
        while True:
            level = input("[*] Enter desired level: ")
            if level not in ['3', '4', '5']:
                print("[!] Invalid input! Please enter 3, 4, or 5.")
            else:
                break
        set_ntlm_settings_script = fr'''
        try {{
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Set-ItemProperty -Path $regPath -Name "LmCompatibilityLevel" -Value {level} -Force
            Write-Output "LmCompatibilityLevel set to {level}."
            exit 0
        }} catch {{
            Write-Output "[-] Failed to set LmCompatibilityLevel: $($_.Exception.Message)"
            exit 1
        }}
        '''
        result = subprocess.run(['powershell.exe', '-Command', set_ntlm_settings_script], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[+] LmCompatibilityLevel set to {level}.")
            return True
        else:
            print("[-] Failed to set LmCompatibilityLevel. Are you running with administrative privileges?")
            print(result.stdout)
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None
    
# 13
# Function to check if ENROLL or ESC1-4 Templates are in use with ADCS
def audit_adcs_settings():
    try:
        print("[*] Checking ADCS for ENROLL and ESC1-4 Templates...")
        audit_adcs_settings_script = '''
        $templates = certutil -catemplates | Where-Object { $_ -match '^(\S+):' } | ForEach-Object { $matches[1] }
        $enrollUsed = $templates -contains 'ENROLL'
        $escUsed = $templates | Where-Object { $_ -match '^ESC[1-4]$' }
        if ($enrollUsed -and $escUsed) {
          exit 3 
        } elseif ($enrollUsed) {
          exit 1 
        } elseif ($escUsed) {
          exit 2 
        } else { 
          exit 0 
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", audit_adcs_settings_script], capture_output=True, text=True)
        if result.returncode == 3:
            print("[-] Both ENROLL and ESC1-4 templates are in use.")
            return False
        elif result.returncode == 1:
            print("[-] The Enroll Template is in use.")
            return False
        elif result.returncode == 2:
            print("[-] The ESC1-4 template is in use.")
            return False
        elif result.returncode == 0:
            print("[+] Neither the ENROLL nor ESC1-4 template is in use.")
            return True
        else:
            print("[!] Unable to check certificate templates!")
            print(result.stdout)
            print(result.stderr)
            return None
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")

# 14
# Function that removes the ENROLL and ESC1-4 templates from ADCS
def harden_adcs():
    try:
        print("[*] Hardening ADCS...")
        harden_adcs_script = r'''
        try {
            $templates = certutil -catemplates | Where-Object { $_ -match '^(\S+):' } | ForEach-Object { $matches[1] }
            $caName = (Get-CertificationAuthority).Name
            $removedEnroll = $false
            $removedEsc = $false
            if ('ENROLL' -in $templates) {
                certutil -config "$env:COMPUTERNAME\$caName" -deltemplate "ENROLL"
                $removedEnroll = $true
            }
            $escTemplates = $templates | Where-Object { $_ -match '^ESC[1-4]$' }
            if ($escTemplates) {
                foreach ($template in $escTemplates) {
                    certutil -config "$env:COMPUTERNAME\$caName" -deltemplate $template
                }
                $removedEsc = $true
            }
            if ($removedEnroll -and $removedEsc) {
              exit 3
            } elseif ($removedEnroll) {
              exit 1 
            } elseif ($removedEsc) { 
              exit 2 
            } else { 
              exit 0
            }
        } catch {
            Write-Output "[-] Error occurred: $($_.Exception.Message)"
            exit 10
        }
        '''
        result = subprocess.run(["powershell.exe", "-Command", harden_adcs_script], capture_output=True, text=True)
        if result.returncode == 3:
            print("[+] ENROLL and ESC1-4 templates removed.")
            return True
        elif result.returncode == 1:
            print("[+] ENROLL template removed.")
            return True
        elif result.returncode == 2:
            print("[+] ESC1-4 template removed.")
            return True
        elif result.returncode == 0: 
            print("[*] ENROLL and ESC1-4 templates already removed.")
            return True
        else:
            print("[!] Error!")
            print(result.stdout)
            print(result.stderr)
            return False
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# 15
# Function that searches for SPNs that have privileges they shouldn't have! (protects against Kerberoasting)
def list_privileged_spns():
    try:
        print("[*] Searching for privileged SPNs...")
        list_privileged_spns_script = r'''
        Import-Module ActiveDirectory -ErrorAction Stop
        $privilegedSpns = @()
        $spns = Get-ADServiceAccount -Filter * | ForEach-Object {
            $spn = $_.servicePrincipalName
            if ($spn) {
                foreach ($entry in $spn) {
                    if ($entry -match '^.*\.(admin|enterprise|domain|root|krbtgt)\..*$') {
                        $privilegedSpns += [PSCustomObject]@{AccountName = $_.Name; SPN = $entry}
                    }
                }
            }
        }
        $privilegedSpns | ConvertTo-Json
        '''
        result = subprocess.run(["powershell.exe", "-Command", list_privileged_spns_script], capture_output=True, text=True)
        if result.returncode == 0:
            spns = json.loads(result.stdout)
        else: 
            print(f"Error getting SPNs: {result.stderr}")
            return None
        print("Privileged SPNs found:")
        for x in spns:
            print(f"Account: {x['AccountName']}, SPN: {x['SPN']}")
        return True
    except Exception as e:
        print(f"[!] Unexpected error!! {e}")
        return None

# Setting up UI for main loop
greeting()
windows_check()
menu()

user_selection = input("[*] Please input your selection: ")

#Main loop
while user_selection != "exit":
    if user_selection == "1":
        is_llmnr_enabled()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "2":
        is_llmnr_enabled_answer = is_llmnr_enabled()
        if is_llmnr_enabled_answer == True:
            disable_llmnr_poisoning()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "3":
        is_netbios_enabled()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "4":
        is_netbios_enabled_answer = is_netbios_enabled()
        if is_netbios_enabled_answer == True:
            disable_netbios()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "5":
        is_smbv1_enabled()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "6":
        is_smbv1_enabled_answer = is_smbv1_enabled()
        if is_smbv1_enabled_answer == True:
            disable_smbv1()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "7":
        check_smb_signing()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "8":
        check_smb_signing_answer = check_smb_signing()
        if check_smb_signing_answer == False:
            enforce_smb_signing()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "9":
        check_wdigest()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "10":
        check_wdigest_answer = check_wdigest()
        if check_wdigest_answer == True:
            disable_wdigest()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "11":
        check_ntlm()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "12":
        set_ntlm_settings()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "13":
        audit_adcs_settings()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "14":
        audit_adcs_settings_answer = audit_adcs_settings()
        if audit_adcs_settings_answer == False:
            harden_adcs()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "15":
        list_privileged_spns()
        user_selection = input("[*] Please input your selection: ")
    elif user_selection == "help":
        menu()
    elif user_selection == "exit":
        sys.exit(0)
        user_selection = input("[*] Please input your selection: ")
    else:
        print("[!] Unexpected Error!!")
        user_selection = input("[*] Please input your selection: ")

