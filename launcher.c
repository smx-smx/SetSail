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
#include <vadefs.h>
#include <windows.h>

#define VAR_EXE_NAME "SS_EXE_NAME"
#define VAR_EXE_ENTRY "SS_EXE_ENTRY"
#define VAR_DLL_NAME "SS_DLL_NAME"

#ifdef _WIN64
#define REG_PC Rip
#elif _WIN32
#define REG_PC Eip
#else
#error "Unsupported architecture"
#endif

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
bool Inject_Dll(const char *dllname, HANDLE hProcess)
{
    HANDLE hThread;
    char szLibPath[_MAX_PATH]; // Buffer to hold the name of the DLL (including full path!)
    void *pLibRemote; // The address (in the remote process) where szLibPath will be copied to.
    DWORD hLibModule; // Base address of loaded module.
    HMODULE hKernel32 = GetModuleHandleA("Kernel32"); // For the LoadLibraryA func.

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
    pLibRemote = VirtualAllocEx(hProcess, NULL, sizeof(szLibPath), MEM_COMMIT, PAGE_READWRITE);

    WriteProcessMemory(hProcess, pLibRemote, (void *)szLibPath, sizeof(szLibPath), NULL);

    // Load "dll" into the remote process by passing LoadLibraryA as the function
    // to run as a thread with CreateRemoteThread. Pass copied name of DLL as
    // the arguments to the function.
    hThread = CreateRemoteThread(
        hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA"), pLibRemote, 0, NULL);

    // Wait for the DLL to load and return.
    WaitForSingleObject(hThread, INFINITE);

    // Get handle of the loaded module
    GetExitCodeThread(hThread, &hLibModule);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pLibRemote, 0, MEM_RELEASE);

    // LoadLibrary return is 0 on failure.
    return hLibModule != 0;
}

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

    HANDLE hProcess = INVALID_HANDLE_VALUE;
    bool success = false;
    do {
        // attempt to load the specified target in suspended state
        if (!CreateProcessA(path, args, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &StartupInfo, &ProcessInformation)) {
            fputs("CreateProcess failed\n", stderr);
            break;
        }
        hProcess = ProcessInformation.hProcess;

        // wait for the process to done
        // locate the entry point

        // patch the entry point with infinite loop
        do {
            if(!VirtualProtectEx(hProcess, entry, sizeof(patchBytes), PAGE_EXECUTE_READWRITE, &oldProtect)){
                fputs("VirtualProtectEx failed\n", stderr);
                break;
            }
            if(!ReadProcessMemory(hProcess, entry, oldBytes, sizeof(patchBytes), &memread)
                || memread != sizeof(patchBytes)
            ){
                fputs("ReadProcessMemory failed\n", stderr);
                break;
            }
            if(!WriteProcessMemory(hProcess, entry, patchBytes, sizeof(patchBytes), &memwritten)
                || memwritten != sizeof(patchBytes)
            ){
                fputs("WriteProcessMemory failed\n", stderr);
                break;
            }       
            if(!VirtualProtectEx(hProcess, entry, sizeof(patchBytes), oldProtect, &oldProtect2)){
                fputs("VirtualProtectEx failed\n", stderr);
                break;
            }
        } while(0);

        // resume the main thread
        if(ResumeThread(ProcessInformation.hThread) == (DWORD)-1){
            fputs("ResumeThread failed\n", stderr);
        }

        // wait until the thread stuck at entry point
        CONTEXT context;
        memset(&context, 0, sizeof(context));

        for (unsigned int i = 0; i < 50 && context.REG_PC != (uintptr_t)entry; ++i) {
            // patience.
            Sleep(100);

            // read the thread context
            context.ContextFlags = CONTEXT_CONTROL;
            if(!GetThreadContext(ProcessInformation.hThread, &context)){
                fputs("GetThreadContext failed\n", stderr);
            }
        }

        if (context.REG_PC != (uintptr_t)entry) {
            // wait timed out, we never got to the entry point :/
            fputs("entry point blockade timed out\n", stderr);
            break;
        }

        // inject DLL payload into remote process
        if (!Inject_Dll(dllname, hProcess)) {
            fputs("dll failed to load\n", stderr);
            break;
        }

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

        // you are ready to go
        if(ResumeThread(ProcessInformation.hThread) == (DWORD)-1){
            fputs("ResumeThread failed\n", stderr);
        }
        success = true;
    } while(0);

    if(!success){
        if(hProcess && hProcess != INVALID_HANDLE_VALUE){
            // terminate the newly spawned process
            if(!TerminateProcess(hProcess, -1)){
                fputs("TerminateProcess failed\n", stderr);
            }
        }
    }
}

bool parse_var_str(const char *name, char **out)
{
    if(!name || !out) return false;
    *out = getenv(name);
    return *out;
}

bool parse_var_ptr(const char *name, LPVOID *out)
{
    if(!name || !out) return false;
    char *v = getenv(name);
    if(!v) return false;
    return sscanf(v, "%p", out) == 1;
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

