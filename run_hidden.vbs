Option Explicit

' Runs a batch file without opening a terminal window.
If WScript.Arguments.Count <> 1 Then WScript.Quit 87

Dim batchPath, shell, command, fso
batchPath = WScript.Arguments(0)
Set fso = CreateObject("Scripting.FileSystemObject")
If Not fso.FileExists(batchPath) Then WScript.Quit 2

Set shell = CreateObject("WScript.Shell")
command = shell.ExpandEnvironmentStrings("%ComSpec%") & " /d /c " & Chr(34) & Chr(34) & batchPath & Chr(34) & Chr(34)
WScript.Quit shell.Run(command, 0, True)
