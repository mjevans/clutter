# Inspired by a script here: https://hinchley.net/articles/changing-window-titles-using-powershell/
# It ran in a loop using a $timer = New-Object System.Timers.Timer
#
# Note, you may also need to make a shortcut https://stackoverflow.com/questions/4037939/powershell-says-execution-of-scripts-is-disabled-on-this-system
# powershell.exe -ExecutionPolicy ByPass -File script.ps1

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class Win32 {
  [DllImport("User32.dll", EntryPoint="SetWindowText")]
  public static extern int SetWindowText(IntPtr hWnd, string strTitle);
}
"@

function Change-Window-Titles($prefix, $result) {
  Get-Process | ? {$_.mainWindowTitle -and $_.mainWindowTitle -like "$($prefix)*"} | %{
    [Win32]::SetWindowText($_.mainWindowHandle, "$($result)")
  }
}

Change-Window-Titles "Minecraft 1." "Minecraft FIXME"
