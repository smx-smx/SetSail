/**
 * @file
 *
 * @author OmniBlade
 *
 * @brief An executable launcher that will inject a dll into the launched process.
 *
 * @copyright SetSail is free software: you can redistribute it and/or
 *            modify it under the terms of the GNU General Public License
 *            as published by the Free Software Foundation, either version
 *            2 of the License, or (at your option) any later version.
 *            A full copy of the GNU General Public License can be found in
 *            LICENSE
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <errhandlingapi.h>
#include <fileapi.h>
#include <processthreadsapi.h>
#include <synchapi.h>
#include <namedpipeapi.h>
#include <windef.h>
#include <winbase.h>
#include <consoleapi.h>
#include <winternl.h>
#include <io.h>
#include <fcntl.h>

#include "common.h"

#ifdef _WIN64
#define REG_PC(ctx) ((ctx).Rip)
#elif _WIN32
#define REG_PC(ctx) ((ctx).Eip)
#else
#error "Unsupported architecture"
#endif

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
);

LPVOID GetMainModuleBase(HANDLE hProcess)
{
    const HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return 0;

    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)(void *)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) return 0;

    PROCESS_BASIC_INFORMATION pbi;
    ULONG retLen = 0;
    const NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
    if (status != 0) return 0;

    // Read ImageBaseAddress from PEB
    PEB remotePEB;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &remotePEB, sizeof(remotePEB), &bytesRead))
        return 0;

    uintptr_t imageBaseAddress = 0;
#if defined(_WIN64)
    imageBaseAddress = *(uintptr_t *)((uintptr_t)&remotePEB + 0x10);
#elif defined(_WIN32)
    imageBaseAddress = *(uintptr_t *)((uintptr_t)&remotePEB + 0x8);
#else
    return 0;
#endif

    BYTE headers[4096] = {0};
    if (!ReadProcessMemory(
            hProcess,
            (LPCVOID)imageBaseAddress,
            headers,
            sizeof(headers),
            &bytesRead))
    {
        fprintf(stderr, "ReadProcessMemory for PE headers failed (0x%"PRIX32").\n", (uint32_t)GetLastError());
        return 0;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)&headers[0];
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)headers + dosHeader->e_lfanew);

    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE
        || dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > sizeof(headers)
        || ntHeaders->Signature != IMAGE_NT_SIGNATURE
    ) {
        fprintf(stderr, "Invalid PE headers\n");
        return 0;
    }
    DWORD entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPVOID entryPointAddress = (PBYTE)imageBaseAddress + entryPointRVA;
    return entryPointAddress;
}

bool Get_Dll_Directory(char *buf, size_t length) {
    HMODULE hModule = NULL;
    if (!GetModuleHandleExA(0
        | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS
        | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&Get_Dll_Directory,
        &hModule
    )) {
        return false;
    }

    GetModuleFileNameA(hModule, buf, length);
    if (GetLastError() != ERROR_SUCCESS) {
        return false;
    }

    char *last = strrchr(buf, '\\');
    if (last) *last = '\0';

    return true;
}

char *Make_Args(const char *exe_name, int argc, char *argv[])
{
    size_t sz = strlen(exe_name) + 3;
    for(int i=1; i<argc; i++){
        sz += 1 + strlen(argv[i]);
    }
    char *buf = calloc(sz, sizeof(char));
    if(!buf) abort();

    sprintf(buf, "\"%s\"", exe_name);
    for(int i=1; i<argc; i++){
        sprintf(buf, " %s", argv[i]);
    }

    return buf;
}


// Based on code from http://www.codeproject.com/Articles/4610/Three-Ways-to-Inject-Your-Code-into-Another-Proces
bool Inject_Dll(const char *dllname, HANDLE hProcess,
    HANDLE *phThread,
    void **ppLibRemote)
{
    char szLibPath[_MAX_PATH]; // Buffer to hold the name of the DLL (including full path!)
    // The address (in the remote process) where szLibPath will be copied to.
    DWORD hLibModule; // Base address of loaded module.
    const HMODULE hKernel32 = GetModuleHandleA("Kernel32"); // For the LoadLibraryA func.

    GetFullPathNameA(dllname, _MAX_PATH, szLibPath, NULL);

    FILE *in = fopen(dllname, "rb");
    if(!in){
        return false;
    }
    IMAGE_NT_HEADERS exe_header;
    DWORD neptr;

    fseek(in, offsetof(IMAGE_DOS_HEADER, e_lfanew), SEEK_CUR);
    fread(&neptr, sizeof(neptr), 1, in);
    rewind(in);
    fread(&exe_header, sizeof(exe_header), 1, in);

    if (!(exe_header.FileHeader.Characteristics & IMAGE_FILE_DLL)) {
        printf("NE char is %x\n",exe_header.FileHeader.Characteristics);
    }

    // 1. Allocate memory in the remote process for szLibPath
    // 2. Write szLibPath to the allocated memory
    void *pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pLibRemote, (void *)szLibPath, sizeof(szLibPath), NULL);

    // Load "dll" into the remote process by passing LoadLibraryA as the function
    // to run as a thread with CreateRemoteThread. Pass copied name of DLL as
    // the arguments to the function.
    HANDLE hThread = CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) (void *) GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0,
        NULL);

    if (!hThread) {
        return false;
    }

    *ppLibRemote = pLibRemote;
    *phThread = hThread;

    return true;
}

#define LOADER_LIBNAME "libloader.dll"


// Based on code snippet from https://opcode0x90.wordpress.com/2011/01/15/injecting-dll-into-process-on-load/
void Inject_Loader(const char *path, LPVOID entry, const char *dllname, char *args)
{
    STARTUPINFOA StartupInfo = {0};
    PROCESS_INFORMATION ProcessInformation;
    DWORD oldProtect;
    DWORD oldProtect2;
    char oldBytes[2];
    char checkBytes[2];
    static const char patchBytes[2] = {'\xEB', '\xFE'}; // JMP $-2
    SIZE_T memwritten;
    SIZE_T memread;

    // initialize the structures
    StartupInfo.cb = sizeof(StartupInfo);

    char dll_dir[_MAX_PATH] = {0};
    char loader_dll_path[_MAX_PATH] = {0};

    HANDLE hProcess = INVALID_HANDLE_VALUE;

    // we read what the child writes
    HANDLE hParentRead = NULL, hChildWrite = NULL;
    // child reads what we write
    HANDLE hChildRead = NULL, hParentWrite = NULL;

    int fdOut = -1, fdIn = -1;
    FILE *fhOut = NULL, *fhIn = NULL;

    bool success = false;
    do {
        if (!Get_Dll_Directory(dll_dir, _countof(dll_dir))) {
            fputs("Get_Dll_Directory failed\n", stderr);
            break;
        }
        if (snprintf(loader_dll_path, sizeof(loader_dll_path), "%s\\"LOADER_LIBNAME, dll_dir) < 0) {
            break;
        }

        SECURITY_ATTRIBUTES sa = {
            .nLength = sizeof(SECURITY_ATTRIBUTES),
            .lpSecurityDescriptor = NULL,
            .bInheritHandle = TRUE
        };
        if (!CreatePipe(&hParentRead, &hChildWrite, &sa, 0)) {
            fputs("CreatePipe failed\n", stderr);
            break;
        }
        if (!CreatePipe(&hChildRead, &hParentWrite, &sa, 0)) {
            fputs("CreatePipe failed\n", stderr);
            break;
        }
        // parent-only read ends
        SetHandleInformation(hParentRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hParentWrite, HANDLE_FLAG_INHERIT, 0);

        char handleStr[32] = {0};
        if (snprintf(handleStr, sizeof(handleStr), "0x%"PRIXPTR, (uintptr_t)hChildRead) < 0) {
            break;
        }
        SetEnvironmentVariable(VAR_PIPE_HANDLE_READ, handleStr);
        if (snprintf(handleStr, sizeof(handleStr), "0x%"PRIXPTR, (uintptr_t)hChildWrite) < 0) {
            break;
        }
        SetEnvironmentVariable(VAR_PIPE_HANDLE_WRITE, handleStr);

        // attempt to load the specified target in suspended state
        if (!CreateProcessA(path, args,
            NULL, NULL, TRUE, CREATE_SUSPENDED,
            NULL, // inherit environment
            NULL, &StartupInfo, &ProcessInformation)) {
            fprintf(stderr, "CreateProcess failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
            break;
            }
        hProcess = ProcessInformation.hProcess;

        fdOut = _open_osfhandle((intptr_t)hParentWrite, _O_WRONLY | O_BINARY);
        if (fdOut < 0) {
            break;
        }
        fdIn = _open_osfhandle((intptr_t)hParentRead, _O_RDONLY | O_BINARY);
        if (fdIn < 0){
            break;
        }

        fhOut = fdopen(fdOut, "wb");
        if (!fhOut) break;
        fhIn = fdopen(fdIn, "rb");
        if (!fhIn) break;

        setvbuf(fhOut, NULL, _IONBF, 0);
        setvbuf(fhIn, NULL, _IONBF, 0);

        if(entry == 0){
            entry = GetMainModuleBase(hProcess);
            if (entry == 0) {
                fputs("Cannot determine base address\n", stderr);
                break;
            }
        }

        LPVOID r_oldBytes = VirtualAllocEx(hProcess, 0, sizeof(oldBytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (r_oldBytes == NULL) {
            fprintf(stderr, "VirtualAllocEx(old bytes) failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
            break;
        }
        if (!WriteProcessMemory(hProcess, r_oldBytes, oldBytes, sizeof(oldBytes), NULL)) {
            fprintf(stderr, "WriteProcessMemory(old bytes) failed(0x%"PRIX32")\n", (uint32_t)GetLastError());
            break;
        }

        // wait for the process to done
        // locate the entry point

        // patch the entry point with infinite loop
        do {
            if(!VirtualProtectEx(hProcess, entry, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect)){
                fprintf(stderr, "VirtualProtectEx failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
                break;
            }
            if(!ReadProcessMemory(hProcess, entry, oldBytes, sizeof(patchBytes), &memread)
                || memread != sizeof(patchBytes)
            ){
                fprintf(stderr, "ReadProcessMemory failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
                break;
            }
            if(!WriteProcessMemory(hProcess, entry, patchBytes, sizeof(patchBytes), &memwritten)
                || memwritten != sizeof(patchBytes)
            ){
                fprintf(stderr, "WriteProcessMemory failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
                break;
            }       
            if(!VirtualProtectEx(hProcess, entry, sizeof(patchBytes), oldProtect, &oldProtect2)){
                fprintf(stderr, "VirtualProtectEx failed (0x%"PRIX32")\n", (uint32_t)GetLastError());
                break;
            }
        } while(0);

        // resume the main thread
        if(ResumeThread(ProcessInformation.hThread) == (DWORD)-1){
            fputs("ResumeThread failed\n", stderr);
        }

        // wait until the thread stuck at entry point
        CONTEXT context = {0};

        for (unsigned int i = 0; i < 50 && REG_PC(context) != (uintptr_t)entry; ++i) {
            // patience.
            Sleep(100);

            // read the thread context
            context.ContextFlags = CONTEXT_CONTROL;
            if(!GetThreadContext(ProcessInformation.hThread, &context)){
                fputs("GetThreadContext failed\n", stderr);
            }
        }

        if (REG_PC(context) != (uintptr_t)entry) {
            // wait timed out, we never got to the entry point :/
            fputs("entry point blockade timed out\n", stderr);
            break;
        }

        const bool free_mem_remote = false;

        HANDLE hThread = NULL;
        void *lpLibNameRemote = NULL;

        // inject DLL payload into remote process
        if (!Inject_Dll(loader_dll_path, hProcess, &hThread, &lpLibNameRemote)) {
            fputs("dll failed to load\n", stderr);
            break;
        }

        char s_ptr[32] = {0};
        do {
            if (free_mem_remote) {
                if (snprintf(s_ptr, sizeof(s_ptr), "0x%"PRIXPTR, (uintptr_t)lpLibNameRemote) < 0) {
                    break;
                }
                cmd_write(fhOut, "SS_I_MEM_FREE", s_ptr);
            }

            char s_hex[(sizeof(oldBytes) * 2) + 1] = {0};
            bytes_to_hex(oldBytes, sizeof(oldBytes), s_hex, sizeof(s_hex));
            cmd_write(fhOut, "SS_I_OLD_BYTES", s_hex);

            if (snprintf(s_ptr, sizeof(s_ptr), "0x%"PRIXPTR, (uintptr_t)entry) < 0) {
                break;
            }
            cmd_write(fhOut, "SS_I_ENTRY", s_ptr);
            if (snprintf(s_ptr, sizeof(s_ptr), "%"PRIuMAX, (uintmax_t)GetThreadId(ProcessInformation.hThread)) < 0) {
                break;
            }
            cmd_write(fhOut, "SS_I_TID", s_ptr);
        } while (false);

        cmd_write(fhOut, "SS_I_END", "");

        bool do_restore = true;
        bool do_resume = true;

        {
            char *var = NULL;
            if (parse_var_str(VAR_RESUME_THREAD, &var) && !strcmp(var, "0")) {
                do_resume = false;
            }
        }

        for (;;) {
            char key[128] = {0};
            char val[128] = {0};
            if (!cmd_read(fhIn, key, sizeof(key), val, sizeof(val))) {
                break;
            }
            printf("%s -> %s\n", key, val);
            if (!strcmp(key, "SS_S_RESTORE")) {
                do_restore = strcmp(val, "0") != 0;
                continue;
            }
            if (!strcmp(key, "SS_S_RESUME")) {
                do_resume = strcmp(val, "0") != 0;
                continue;
            }
            if (!strcmp(key, "_END")) {
                cmd_write(fhOut, "_END", "");
                break;
            }
        }

        // Wait for DllMain to return
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);

        if (!free_mem_remote) {
            if (!VirtualFreeEx(hProcess, lpLibNameRemote, 0, MEM_RELEASE)) {
                fputs("VirtualFreeEx failed\n", stderr);
            }
        }

        if (do_restore) {
            // pause and restore original entry point unless DLL init overwrote
            // it already.
            if(SuspendThread(ProcessInformation.hThread) == (DWORD)-1){
                fputs("SuspendThread failed\n", stderr);
            }
            if(!VirtualProtectEx(hProcess, entry, 2, PAGE_EXECUTE_READWRITE, &oldProtect)){
                fputs("VirtualProtectEx failed\n", stderr);
            }
            if(!ReadProcessMemory(hProcess, entry, checkBytes, sizeof(patchBytes), &memread)
                || memread != sizeof(patchBytes)
            ){
                fputs("ReadProcessMemory failed\n", stderr);
            }

            // Check entry point is still patched to infinite loop. We don't
            // want to mess up any patching the DLL did.
            if (memcmp(checkBytes, patchBytes, sizeof(patchBytes)) == 0) {
                if(!WriteProcessMemory(hProcess, entry, oldBytes, sizeof(patchBytes), &memwritten)
                    || memwritten != sizeof(patchBytes)
                ){
                    fputs("WriteProcessMemory failed\n", stderr);
                }
            }

            if(!VirtualProtectEx(hProcess, entry, 2, oldProtect, &oldProtect2)){
                fputs("VirtualProtectEx failed\n", stderr);
            }

            // MessageBox(NULL, "Attach debugger or continue.", "game.dat Debug Time!", MB_OK|MB_SERVICE_NOTIFICATION);

            if (do_resume) {
                puts("do_resume");
                // you are ready to go
                if(ResumeThread(ProcessInformation.hThread) == (DWORD)-1){
                    fputs("ResumeThread failed\n", stderr);
                }
            }
        }

        success = true;
    } while(0);

    if (fhIn) fclose(fhIn);
    if (fhOut) fclose(fhOut);
    if (fdIn >= 0) close(fdIn);
    if (fdOut >= 0) close(fdOut);
    if (hParentWrite) CloseHandle(hParentWrite);
    if (hParentRead) CloseHandle(hParentRead);
    if (hChildRead) CloseHandle(hChildRead);
    if (hChildWrite) CloseHandle(hChildWrite);

    if(!success){
        if(hProcess && hProcess != INVALID_HANDLE_VALUE){
            // terminate the newly spawned process
            if(!TerminateProcess(hProcess, -1)){
                fputs("TerminateProcess failed\n", stderr);
            }
        }
    }
}

int main(int argc, char *argv[])
{
#ifndef __WATCOMC__
    AttachConsole(ATTACH_PARENT_PROCESS);
#endif

    char *exe_name = NULL;
    char *dll_name = NULL;
    LPVOID exe_entry = NULL;

    int rc = EXIT_SUCCESS;
    if(!parse_var_str(VAR_EXE_NAME, &exe_name)){
        fputs(VAR_EXE_NAME " not defined\n", stderr);
        rc = EXIT_FAILURE;
    }
    if(!parse_var_str(VAR_DLL_NAME, &dll_name)){
        fputs(VAR_DLL_NAME " not defined\n", stderr);
        rc = EXIT_FAILURE;
    }
    if(!parse_var_ptr(VAR_EXE_ENTRY, &exe_entry)){
        fputs(VAR_EXE_ENTRY " not defined\n", stderr);
        rc = EXIT_FAILURE;
    }

    if(rc != EXIT_SUCCESS){
        return rc;
    }

    char *cmdline = Make_Args(exe_name, argc, argv);
    Inject_Loader(exe_name, exe_entry, dll_name, cmdline);
    free(cmdline);
    Sleep(1000);
    return rc;
}

