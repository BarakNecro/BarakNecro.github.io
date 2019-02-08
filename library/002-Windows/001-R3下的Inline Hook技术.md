# R3下的Inline Hook技术

> 标签： Windows Hook Inline

[TOC]

## 项目信息

### 基本内容

 - 项目编号：FHO-0001
 - 项目等级：**初级**
 - 内容分类：明理 记录
 - 项目简介：*Windows R3下的Inline Hook*
 - 最后更新：2018-07-26 08:10:00

### 依赖知识

 1. 汇编语言与C语言[^1]
 2. Visual Studio的使用[^2]
 3. [DLL文件介绍](http://www.baidu.com)
 3. [Windows R3下的代码注入技术](http://www.baidu.com)

### 存储方式
 
  - [x] 原始文档
  - [x] 知识库
  - [ ] 记忆库
 
## 核心知识

### 一、Inline Hook

#### 简介

Inline Hook应该说是最朴素思想的一种Hook技术。通过直接修改原代码（是原代码不是源代码，之后用 **原函数** 的说法替换）跳转到自己的逻辑中执行。之后有可能跳回来，也有可能就此不管，也有可能在某个时间点还原被Hook的代码，一切随作者心意。之所以称之为Inline，也正是因为**这种Hook方式直接改变了原函数的运行逻辑**，就如同原函数中的一个内联函数一般，故如此命名。
 
#### Inline Hook的流程

实现的手法固然各有差异，流程一般如下：

```flow
st=>start: 编写用于替换原函数的Hook函数【Hook函数】
o1=>operation: 编写跳转到【Hook函数】的代码【跳转Code】（一般由汇编实现）
o2=>operation: 寻找原函数所在内存
o3=>operation: 解除原函数所在内存的读写保护
o4=>operation: 保存原函数入口处若干字节（由具体跳转代码的字节数决定）的代码【原入口代码】
o5=>operation: 修改【原入口代码】为【跳转代码】
o6=>operation: 恢复原函数所在内存的读写保护
o6=>operation: 函数被调用……
o7=>operation: 不需要继续Hook时，用【原入口代码】还原【跳转Code】
ep=>end: 结束

st->o1->o2->o3->o4->o5->o6->o7->ep
```

接下来用一案例结合代码实际演示Inline Hook技术。

#### Inline Hook实战

通过对 *Windows任务管理器* 的`TerminateProcess`函数进行Inline Hook，使其不能关闭其他进程。

在正式开始之前，要先说明几个容易踩坑的地方。

 1. x86下做Inline hook与x64下不太一样，主要是【跳转代码】编写方式不同。
 因为x86下JMP指令可以非常随意的在长达前后2G的内存空间里跳转，因此通过`JMP 0x????????` 这种形式的代码即可完成几乎所有跳转工作，16进制机器码形式即 0xE9 + 4字节内存空间（注意低位优先存储），只需要5个字节即可完成【跳转代码】。
 内存空间计算方式为：**【Hook函数】内存入口地址 - 【原代码】内存入口地址 - 【跳转代码】长度（此处即5字节）**。
在x64架构下，内存地址长度变为8个字节，JMP指令无法支持这么长的内存地址（8个字节），因此要靠下面这种方式来完成跳转：
```x86asm
mov rax,0x????????????????
push rax
ret
```
 即利用栈存储地址，然后return到指定的地址去，从而完成远跳转。
 16进制机器码为 `48H B8H XX XX XX XX XX XX XX XX 50H C3H` 共12个字节。
 **中间的8个字节就是要压入栈顶的内存地址**。
 
2.  建议用`void*`这种方式来存储函数的地址，这个指针的长度在x86下是4字节，在x64下是8字节，比起`long`不知道高到哪里去。

下面先来编写用于执行Inline Hook的DLL文件：

```cpp
//X86版
// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include <Windows.h>


//禁止结束进程
BOOL
WINAPI
MyTerminateProcess(
_In_ HANDLE hProcess,
_In_ UINT uExitCode
){
	MessageBox(NULL, L"拒绝关闭哦！ By Taoist.SJ", L"提示", MB_OK);
	return FALSE;
}

BOOL Hook(DWORD srcFunctionAddress,DWORD dstFunctionAddress,BYTE* oldCode);

BOOL UnHook(DWORD srcFunctionAddress, BYTE* oldCode, int size);

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	BYTE originCode[5];
	DWORD OriginTerminateProcessAddress = 0;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		OriginTerminateProcessAddress = (DWORD)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "TerminateProcess");
		Hook(OriginTerminateProcessAddress, (DWORD)MyTerminateProcess, originCode);
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (OriginTerminateProcessAddress != 0){
			UnHook(OriginTerminateProcessAddress, originCode, sizeof(originCode) / sizeof(BYTE));
		}
		break;
	}
	return TRUE;
}

BOOL Hook(DWORD srcFunctionAddress, DWORD dstFunctionAddress, BYTE* oldCode){
	DWORD pflag1 = 0, pflag2 = 0;
	BYTE jumpCode[5] = { 0xE9, 0, 0, 0, 0 };
	DWORD offect = 0;
	int jumpCodeSize = sizeof(jumpCode) / sizeof(BYTE);
	offect = dstFunctionAddress - srcFunctionAddress - jumpCodeSize;
	for (int i = 1; i < jumpCodeSize; i++){
		jumpCode[i] = *((BYTE*)&offect + i - 1);
	}
	
	VirtualProtect((VOID*)srcFunctionAddress, jumpCodeSize, PAGE_EXECUTE_READWRITE, &pflag1);
	for (int i = 0; i < jumpCodeSize; i++){
		*(oldCode + i) = *((BYTE*)srcFunctionAddress + i);
		*((BYTE*)srcFunctionAddress + i) = jumpCode[i];
	}
	VirtualProtect((VOID*)srcFunctionAddress, jumpCodeSize, pflag1, &pflag2);
	return TRUE;
}

BOOL UnHook(DWORD srcFunctionAddress, BYTE* oldCode, int size){
	DWORD pflag1 = 0, pflag2 = 0;
	VirtualProtect((VOID*)srcFunctionAddress, size, PAGE_EXECUTE_READWRITE, &pflag1);
	for (int i = 0; i < size; i++){
		*((BYTE*)srcFunctionAddress + i) = *(oldCode + i);
	}
	VirtualProtect((VOID*)srcFunctionAddress, size, pflag1, &pflag2);
	return TRUE;
}
```

然后是x64版：

然后再来编写用于注入DLL到任务管理器的注入器工具，使用最简单的**远线程注入技术**来搞定。
```cpp
#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

HMODULE injectDLL(HANDLE process, WCHAR *dllFileName);

void main(){
	DWORD pid = -1;
	GetWindowThreadProcessId(FindWindow(NULL, L"Windows 任务管理器"),&pid);
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	injectDLL(processHandle, L"\\InjectDllProject.dll");
	TerminateProcess(NULL, -1);
}

HMODULE injectDLL(HANDLE process , WCHAR *dllFileName){
	WCHAR dllPath[256];
	HANDLE remoteThreadHandle = NULL;
	DWORD remoteThreadExitCode = 0;

	GetCurrentDirectory(_countof(dllPath),dllPath);
	lstrcat(dllPath, dllFileName);
	
	VOID *parameterAddr = VirtualAllocEx(process, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(process, parameterAddr, dllPath, sizeof(dllPath), NULL);
	
	remoteThreadHandle = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibrary, parameterAddr, 0, NULL);

	WaitForSingleObject(remoteThreadHandle, INFINITE);

	//X86下可通过这种方法获取远线程在目标进程里的模块句柄
	//X64下该方法不好使，需要重新从系统快照中搜索
	GetExitCodeThread(remoteThreadHandle, &remoteThreadExitCode);

	CloseHandle(remoteThreadHandle);

	return (HMODULE)remoteThreadExitCode;
}
```

## 结果展示
![Alt text](amWiki/images/post/1532596646961.png)


[^1]:所需的C语言与汇编语言知识

[^2]:Visual Studio的基础操作