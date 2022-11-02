---
title: Powershell
date: 2022-5-25
password: GWTWL
tags: 内网
categories: Technology
---

[toc]



# 基础



## 变量

以`$`开头，大小写不敏感。

## 数组

```powershell
$array = 1,2,3,4
$array = 1..4
$array=1,"2017",([System.Guid]::NewGuid()),(get-date)
$a=@()  # 空数组
$a=,"1" # 一个元素的数组

#访问
$ip = ipconfig
$ip[1] # 获取ipconfig第二行的数据

#判断
$test -is [array]
#追加
$books += "元素4"
```



## 哈希表

```powershell
#创建
$stu=@{ Name = "test";Age="12";sex="man" }
$stu=@{ Name = "hei";Age="12";sex="man";Books="kali","sqlmap","powershell" }
#插入删除
$Student=@{}
$Student.Name="hahaha"
$stu.Remove("Name")
```



## 对象

### 查看对象结构 Get-Member

由于对象在 Windows PowerShell 中扮演了如此重要的角色，因此存在几个用于处理任意对象类型的本机命令。 最重要的一个是 Get-Member 命令。

```powershell
Get-Process | Get-Member | Out-Host -Paging
TypeName: System.Diagnostics.Process

Name                           MemberType     Definition
----                           ----------     ----------
Handles                        AliasProperty  Handles = Handlecount
Name                           AliasProperty  Name = ProcessName
NPM                            AliasProperty  NPM = NonpagedSystemMemorySize
PM                             AliasProperty  PM = PagedMemorySize
VM                             AliasProperty  VM = VirtualMemorySize
WS                             AliasProperty  WS = WorkingSet
add_Disposed                   Method         System.Void add_Disposed(Event...
...
```

我们可以通过筛选想要查看的元素，让这个冗长的信息列表更易于使用。 Get-Member 命令仅允许你列出属性成员。 属性的形式有数种。 如果将 Get-Member MemberType 参数设置为值属性，则 cmdlet 将显示任何类型的属性 。 生成的列表仍会很长，但较之前更易于管理：

```powershell
PS C:\Users\86177> Get-Process|Get-Member -MemberType AliasProperty


   TypeName:System.Diagnostics.Process

Name    MemberType    Definition
----    ----------    ----------
Handles AliasProperty Handles = Handlecount
Name    AliasProperty Name = ProcessName
NPM     AliasProperty NPM = NonpagedSystemMemorySize64
PM      AliasProperty PM = PagedMemorySize64
SI      AliasProperty SI = SessionId
VM      AliasProperty VM = VirtualMemorySize64
WS      AliasProperty WS = WorkingSet64
```



### 选择对象部件Select-Object

可以使用 Select-Object cmdlet 创建新的自定义 PowerShell 对象（包含从用于创建它们的对象中选择的属性）。 键入下面的命令以创建仅包括 Win32_LogicalDisk WMI 类的 Name 和 FreeSpace 属性的新对象：

```powershell
PS C:\Users\86177> Get-CimInstance -Class Win32_LogicalDisk | Select-Object -Property Name,FreeSpace

Name    FreeSpace
----    ---------
C:      182464512
D:    43895218176
E:   345713266688
```

可以使用 Select-Object 创建计算属性。 这样即可以以十亿字节为单位显示 FreeSpace，而非以字节为单位。

```powershell
PS C:\Users\86177> Get-CimInstance -Class Win32_LogicalDisk |
>>   Select-Object -Property Name, @{
>>     label='FreeSpace'
>>     expression={($_.FreeSpace/1GB).ToString('F2')}
>>   }

Name FreeSpace
---- ---------
C:   1.76
D:   40.88
E:   321.97
```



### 创建.Net对象

存在具有 .NET Framework 和 COM 接口的软件组件，使用它们可执行许多系统管理任务。 Windows PowerShell 允许你使用这些组件，因此你将不限于执行可通过使用 cmdlet 执行的任务。 Windows PowerShell 初始版本中的许多 cmdlet 对远程计算机无效。 我们将演示如何通过直接从 Windows PowerShell 使用 .NET Framework System.Diagnostics.EventLog 类在管理事件日志时绕过此限制。

#### 使用 New-Object 进行事件日志访问

.NET Framework 类库包括一个名为 System.Diagnostics.EventLog 的类，该类可用于管理事件日志。 可以通过使用具有 TypeName 参数的 New-Object cmdlet 创建 .NET Framework 类的新实例。 例如，以下命令将创建事件日志引用：



```powershell
PS C:\Users\yutao> New-Object -TypeName System.Diagnostics.EventLog

  Max(K) Retain OverflowAction        Entries Log
  ------ ------ --------------        ------- ---


```

该命令创建了 EventLog 类的实例，但该实例不包含任何数据。 这是因为我们未指定特定的事件日志。 如何获取真正的事件日志？

#### 将构造函数与 New-Object 一起使用

若要引用特定的事件日志，需要指定日志的名称。 New-Object 具有 ArgumentList 参数。 作为值传递到此形参的实参将由对象的特殊的启动方法使用。 此方法叫做构造函数，因为它将用于构造对象。 例如，若要对获取应用程序日志的引用，请指定字符串“Application”作为实参

```powershell
PS C:\Users\yutao> New-Object -TypeName System.Diagnostics.EventLog -ArgumentList Application

  Max(K) Retain OverflowAction        Entries Log
  ------ ------ --------------        ------- ---
  20,480      0 OverwriteAsNeeded         752 Application

```

#### 在变量中存储对象

你可能需要存储对对象的引用，以便在当前的 Shell 中使用。 尽管 Windows PowerShell 允许使用管道执行大量操作，减少了对变量的需求，但有时在变量中存储对对象的引用可以更方便地操纵这些对象。 Windows PowerShell 允许你创建实质上是命名对象的变量。 来自任何有效 Windows PowerShell 命令的输出都可以存储在变量中。 变量名始终以 $ 开头。 如果想要将应用程序日志引用存储在名为 $AppLog 的变量中，请键入该变量的名称，后跟一个等号，然后键入用于创建应用程序日志对象的命令：

```powershell
PS C:\Users\yutao> $AppLog = New-Object -TypeName System.Diagnostics.EventLog -ArgumentList Application
PS C:\Users\yutao> $AppLog

  Max(K) Retain OverflowAction        Entries Log
  ------ ------ --------------        ------- ---
  20,480      0 OverwriteAsNeeded         752 Application

```

#### 使用 New-Object 访问远程事件日志

上一节中使用的命令以本地计算机为目标；Get-EventLog cmdlet 可做到这一点。 若要访问远程计算机上的应用程序日志，必须同时将日志名称和计算机名称（或 IP 地址）作为参数提供。

```powershell
PS> $RemoteAppLog = New-Object -TypeName System.Diagnostics.EventLog Application,192.168.1.81
PS> $RemoteAppLog

  Max(K) Retain OverflowAction        Entries Name
  ------ ------ --------------        ------- ----
     512      7 OverwriteOlder            262 Application
```

#### 使用对象方法清除事件日志

对象通常具有可调用以执行任务的方法。 可以使用 Get-Member 来显示与对象关联的方法。 下面的命令和已选的输出将显示 EventLog 类的一些方法：

```powershell
PS C:\Users\yutao> $RemoteAppLog | Get-Member -MemberType Method


   TypeName:System.Diagnostics.EventLog

Name                      MemberType Definition
----                      ---------- ----------
BeginInit                 Method     void BeginInit(), void ISupportInitialize.BeginInit()
Clear                     Method     void Clear()
Close                     Method     void Close()
CreateObjRef              Method     System.Runtime.Remoting.ObjRef CreateObjRef(type requestedType)
Dispose                   Method     void Dispose(), void IDisposable.Dispose()
EndInit                   Method     void EndInit(), void ISupportInitialize.EndInit()
Equals                    Method     bool Equals(System.Object obj)
GetHashCode               Method     int GetHashCode()
GetLifetimeService        Method     System.Object GetLifetimeService()
GetType                   Method     type GetType()
InitializeLifetimeService Method     System.Object InitializeLifetimeService()
ModifyOverflowPolicy      Method     void ModifyOverflowPolicy(System.Diagnostics.OverflowAction action, int retentionDays)
RegisterDisplayName       Method     void RegisterDisplayName(string resourceFile, long resourceId)
ToString                  Method     string ToString()
WriteEntry                Method     void WriteEntry(string message), void WriteEntry(string message, System.Diagnostics.EventLogEntryType type), void WriteEntry(string message, System.Diagnostics.EventLogEntryType type, i...
WriteEvent                Method     void WriteEvent(System.Diagnostics.EventInstance instance, Params System.Object[] values), void WriteEvent(System.Diagnostics.EventInstance instance, byte[] data, Params System.Object[]...

```

Clear() 方法可以用于清除事件日志。 调用方法时，即使该方法不需要参数，也必须始终在方法名称后紧跟括号。 这使得 Windows PowerShell 方法能够区分该方法和具有相同名称的潜在属性。 键入以下命令以调用 Clear 方法

```powershell
PS C:\Users\yutao> $RemoteAppLog.Clear()
```

### 使用 New-Object 创建 COM 对象

可以使用 New-Object 来处理组件对象模型 (COM) 组件。 组件的范围从 Windows 脚本宿主 (WSH) 包含的各种库到 ActiveX 应用程序（如大多数系统上安装的 Internet Explorer）。

New-Object 使用 .NET Framework 运行时可调用的包装器创建 COM 对象，因此调用 COM 对象时它与 .NET Framework 具有相同的限制。 若要创建 COM 对象，需要为 ComObject 参数指定要使用的 COM 类的编程标识符（或 ProgId）。 COM 用途限制的全面讨论和确定系统上可用的 ProgId 已超出本用户指南的范围，但来自环境的大多数已知对象（如 WSH）都可在 Windows PowerShell 内使用。

可以通过指定以下 progid 来创建 WSH 对象：WScript.Shell 、WScript.Network 、Scripting.Dictionary 和 Scripting.FileSystemObject 。 以下命令将创建这些对象：

```powershell
New-Object -ComObject WScript.Shell
New-Object -ComObject WScript.Network
New-Object -ComObject Scripting.Dictionary
New-Object -ComObject Scripting.FileSystemObject
```



#### 使用 WScript.Shell 创建桌面快捷方式



可以使用 COM 对象快速执行的一个任务是创建快捷方式。 假设你想要在桌面上创建链接到 Windows PowerShell 主文件夹的快捷方式。 首先需要创建对 WScript.Shell 的引用，我们会将其存储在名为 $WshShell 的变量中：

```powershell
 $WshShell = New-Object -ComObject WScript.Shell
 PS C:\Users\yutao> $WshShell | Get-Member


   TypeName:System.__ComObject#{41904400-be18-11d3-a28b-00104bd35090}

Name                     MemberType            Definition
----                     ----------            ----------
AppActivate              Method                bool AppActivate (Variant, Variant)
CreateShortcut           Method                IDispatch CreateShortcut (string)
Exec                     Method                IWshExec Exec (string)
ExpandEnvironmentStrings Method                string ExpandEnvironmentStrings (string)
LogEvent                 Method                bool LogEvent (Variant, string, string)
Popup                    Method                int Popup (string, Variant, Variant, Variant)
RegDelete                Method                void RegDelete (string)
RegRead                  Method                Variant RegRead (string)
RegWrite                 Method                void RegWrite (string, Variant, Variant)
Run                      Method                int Run (string, Variant, Variant)
SendKeys                 Method                void SendKeys (string, Variant)
Environment              ParameterizedProperty IWshEnvironment Environment (Variant) {get}
CurrentDirectory         Property              string CurrentDirectory () {get} {set}
SpecialFolders           Property              IWshCollection SpecialFolders () {get}

```

Get-Member 具有可选 InputObject 参数，你可以使用这个参数而不使用管道为 Get-Member 提供输入。 如果改用命令 Get-Member-InputObject $WshShell，你会得到与如上所示相同的输出。 如果使用 InputObject，它将视其参数为单个项。 这意味着，如果变量中有几个对象，那么 Get-Member 会将它们视为一个对象数组。 例如：

```powershell
PS C:\Users\yutao> $a = 1,2,"three"
PS C:\Users\yutao> Get-Member -InputObject $a


   TypeName:System.Object[]

Name           MemberType            Definition
----           ----------            ----------
Count          AliasProperty         Count = Length
Add            Method                int IList.Add(System.Object value)
Address        Method                System.Object&, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089 Address(int )
Clear          Method                void IList.Clear()
Clone          Method                System.Object Clone(), System.Object ICloneable.Clone()
CompareTo      Method                int IStructuralComparable.CompareTo(System.Object other, System.Collections.IComparer comparer)
Contains       Method                bool IList.Contains(System.Object value)
....
```

WScript.Shell CreateShortcut 方法接受单个参数，即要创建的快捷方式文件的路径。 我们可以键入桌面的完整路径，但还有更简单的方法。 桌面通常由当前用户的主文件夹内名为 Desktop 的文件夹表示。 Windows PowerShell 具有变量 $Home，它包含此文件夹的路径。 我们可以通过使用此变量指定主文件夹的路径，然后通过键入以下内容添加 Desktop 文件夹的名称和要创建的快捷方式的名称：

```powershell
$lnk = $WshShell.CreateShortcut("$Home\Desktop\PSHome.lnk")
```

当你在双引号内使用外观类似变量名称的项时，Windows PowerShell 将尝试替换匹配的值。 如果使用单引号，Windows PowerShell 将不会替换该变量值。 例如，请尝试键入以下命令

```powershell
PS> "$Home\Desktop\PSHome.lnk"
C:\Documents and Settings\aka\Desktop\PSHome.lnk
PS> '$Home\Desktop\PSHome.lnk'
$Home\Desktop\PSHome.lnk
```



## 控制语句



```powershell
-eq ：等于
-ne ：不等于
-gt ：大于
-ge ：大于等于
-lt ：小于
-le ：小于等于
-contains ：包含
$array -contains something

-notcontains :不包含
!($a): 求反
-and ：和
-or ：或
-xor ：异或
-not ：逆

if-else:

if($value -eq 1){
    code1
}else{
    code2
}
```

循环语句：

```powershell
while($n -gt 0){
    code
}


$sum=0
for($i=1;$i -le 100;$i++)
{
    $sum+=$i
}
$sum

# 打印出windows目录下大于1mb的文件名
foreach($file in dir c:\windows)
{
    if($file.Length -gt 1mb)
    {
        $File.Name
    }
}
```























































