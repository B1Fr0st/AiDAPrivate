param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not ('AidaC03PathIdentityNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class AidaC03PathIdentityNative
{
    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_ATTRIBUTE_TAG_INFO
    {
        public uint FileAttributes;
        public uint ReparseTag;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateFileW(string path, uint access, uint share, IntPtr security, uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandleEx(IntPtr handle, int informationClass, out FILE_ATTRIBUTE_TAG_INFO information, uint size);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint GetFinalPathNameByHandleW(IntPtr handle, StringBuilder path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
}

if ([string]::IsNullOrEmpty($Path) -or $Path.Length -lt 3 -or $Path.Length -gt 32767 -or
    $Path -cnotmatch '^[A-Z]:/' -or $Path.Contains('\') -or $Path.Contains('//') -or
    $Path.EndsWith('/', [StringComparison]::Ordinal) -or
    $Path -cmatch '(^|/)\.?\.(/|$)') {
    throw 'AIDA_C03_PATH_IDENTITY_RAW'
}

$segments = @($Path.Substring(3).Split('/'))
foreach ($character in $Path.ToCharArray()) {
    if ([int]$character -lt 0x20 -or [int]$character -gt 0x7e) {
        throw 'AIDA_C03_PATH_IDENTITY_RAW'
    }
}
foreach ($segment in $segments) {
    if ([string]::IsNullOrEmpty($segment) -or
        $segment.EndsWith('.', [StringComparison]::Ordinal) -or
        $segment.EndsWith(' ', [StringComparison]::Ordinal) -or
        $segment.IndexOf(':', [StringComparison]::Ordinal) -ge 0) {
        throw 'AIDA_C03_PATH_IDENTITY_RAW'
    }
}
$current = $Path.Substring(0, 3)
$final = $null
for ($index = -1; $index -lt $segments.Count; ++$index) {
    if ($index -ge 0) {
        $current += $(if ($current.EndsWith('/', [StringComparison]::Ordinal)) { '' } else { '/' }) + $segments[$index]
    }
    $handle = [AidaC03PathIdentityNative]::CreateFileW(
        $current, 0, 7, [IntPtr]::Zero, 3, 0x02200000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) {
        throw 'AIDA_C03_PATH_IDENTITY_OPEN'
    }
    try {
        $tag = New-Object AidaC03PathIdentityNative+FILE_ATTRIBUTE_TAG_INFO
        if (-not [AidaC03PathIdentityNative]::GetFileInformationByHandleEx(
                $handle, 9, [ref]$tag,
                [Runtime.InteropServices.Marshal]::SizeOf([type]'AidaC03PathIdentityNative+FILE_ATTRIBUTE_TAG_INFO'))) {
            throw 'AIDA_C03_PATH_IDENTITY_TAG'
        }
        if (($tag.FileAttributes -band 0x400) -ne 0 -or $tag.ReparseTag -ne 0) {
            throw 'AIDA_C03_PATH_IDENTITY_REPARSE'
        }
        $buffer = New-Object Text.StringBuilder 32768
        $length = [AidaC03PathIdentityNative]::GetFinalPathNameByHandleW($handle, $buffer, 32768, 0)
        if ($length -eq 0 -or $length -ge 32768) {
            throw 'AIDA_C03_PATH_IDENTITY_FINAL'
        }
        $final = $buffer.ToString()
        if ($final.StartsWith('\\?\', [StringComparison]::Ordinal)) {
            $final = $final.Substring(4)
        }
        $final = $final.Replace('\', '/')
        if ($index -lt 0 -and -not $final.EndsWith('/', [StringComparison]::Ordinal)) {
            $final += '/'
        }
        if (-not [string]::Equals($final, $current, [StringComparison]::Ordinal)) {
            throw 'AIDA_C03_PATH_IDENTITY_CASE'
        }
    } finally {
        [AidaC03PathIdentityNative]::CloseHandle($handle) | Out-Null
    }
}

[Console]::Out.Write($final)
