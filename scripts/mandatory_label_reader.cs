using System;
using System.ComponentModel;
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("TenderBot Mandatory Label Reader")]
[assembly: AssemblyDescription("Read-only Windows mandatory integrity label reader")]
[assembly: AssemblyCompany("TenderBot")]
[assembly: AssemblyProduct("TenderBot Live Inbound")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

namespace TenderBot.LiveInbound.Security
{
    public static class MandatoryLabelReader
    {
        private const uint LabelSecurityInformation = 0x00000010;
        private const int FileObject = 1;
        private const uint SddlRevision1 = 1;

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            EntryPoint = "GetNamedSecurityInfoW"
        )]
        private static extern uint GetNamedSecurityInfo(
            string name,
            int objectType,
            uint securityInformation,
            IntPtr owner,
            IntPtr group,
            out IntPtr dacl,
            out IntPtr sacl,
            out IntPtr securityDescriptor
        );

        [DllImport(
            "advapi32.dll",
            CharSet = CharSet.Unicode,
            EntryPoint = "ConvertSecurityDescriptorToStringSecurityDescriptorW",
            SetLastError = true
        )]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptor(
            IntPtr securityDescriptor,
            uint revision,
            uint securityInformation,
            out IntPtr text,
            out uint textLength
        );

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static string Read(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException("A filesystem path is required.", "path");

            IntPtr dacl;
            IntPtr sacl;
            IntPtr descriptor;
            uint error = GetNamedSecurityInfo(
                path,
                FileObject,
                LabelSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                out dacl,
                out sacl,
                out descriptor
            );
            if (error != 0)
                throw new Win32Exception((int)error);

            try
            {
                IntPtr text;
                uint textLength;
                if (!ConvertSecurityDescriptorToStringSecurityDescriptor(
                    descriptor,
                    SddlRevision1,
                    LabelSecurityInformation,
                    out text,
                    out textLength
                ))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                try
                {
                    if (text == IntPtr.Zero || textLength < 2)
                    {
                        throw new InvalidOperationException(
                            "Mandatory integrity label SDDL is empty."
                        );
                    }
                    return Marshal.PtrToStringUni(
                        text,
                        checked((int)textLength - 1)
                    );
                }
                finally
                {
                    if (text != IntPtr.Zero)
                        LocalFree(text);
                }
            }
            finally
            {
                if (descriptor != IntPtr.Zero)
                    LocalFree(descriptor);
            }
        }
    }
}
