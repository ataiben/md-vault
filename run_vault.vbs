Option Explicit

Dim fso, shell, scriptDir, pyCandidates, candidate, chosenPy
Set fso = CreateObject("Scripting.FileSystemObject")
Set shell = CreateObject("WScript.Shell")

scriptDir = fso.GetParentFolderName(WScript.ScriptFullName)
shell.CurrentDirectory = scriptDir

pyCandidates = Array( _
    scriptDir & "\.venv\Scripts\pythonw.exe", _
    scriptDir & "\venv\Scripts\pythonw.exe" _
)

chosenPy = ""
For Each candidate In pyCandidates
    If fso.FileExists(candidate) Then
        chosenPy = """" & candidate & """"
        Exit For
    End If
Next

If chosenPy = "" Then
    chosenPy = "pythonw"
End If

On Error Resume Next
shell.Run chosenPy & " """ & scriptDir & "\app.py""", 0, False
If Err.Number <> 0 Then
    MsgBox "未能启动 MD-Vault：未检测到 Python 运行环境。" & vbCrLf & vbCrLf & _
           "请先安装 Python 3.9+，并在项目目录执行：" & vbCrLf & _
           "pip install -r requirements.txt", vbExclamation, "MD-Vault 启动提示"
End If
On Error GoTo 0
