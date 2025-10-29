#include <stdio.h>
#include <stdbool.h>
#include <minwindef.h>
#include <io.h>
#include <fcntl.h>
#include <handleapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <processenv.h>

#include "common.h"

void dll_main() {
    char *dll_name = NULL;
    HANDLE hPipeRead = NULL, hPipeWrite = NULL;
    int fdWrite = -1, fdRead = -1;
    FILE *fhWrite = NULL, *fhRead = NULL;
    do {
        if (!parse_var_str(VAR_DLL_NAME, &dll_name)) {
            fputs(VAR_DLL_NAME " not defined\n", stderr);
            break;
        }
        if (!parse_var_ptr(VAR_PIPE_HANDLE_READ, &hPipeRead)) {
            fputs(VAR_PIPE_HANDLE_READ " not defined\n", stderr);
            break;
        }
        if (!parse_var_ptr(VAR_PIPE_HANDLE_WRITE, &hPipeWrite)) {
            fputs(VAR_PIPE_HANDLE_WRITE " not defined\n", stderr);
            break;
        }
        fdWrite = _open_osfhandle((intptr_t)hPipeWrite, _O_WRONLY | O_BINARY);
        if (fdWrite < 0) {
            fputs("_open_osfhandle() failed\n", stderr);
            break;
        }
        fdRead = _open_osfhandle((intptr_t)hPipeRead, _O_RDONLY | O_BINARY);
        if (fdRead < 0) {
            fputs("_open_osfhandle() failed\n", stderr);
            break;
        }
        fhWrite = fdopen(fdWrite, "wb");
        if (!fhWrite) {
            fputs("fdopen failed\n", stderr);
            break;
        }
        fhRead = fdopen(fdRead, "rb");
        if (!fhRead) {
            fputs("fdopen failed\n", stderr);
            break;
        }

        setvbuf(fhWrite, NULL, _IONBF, 0);
        setvbuf(fhRead, NULL, _IONBF, 0);

        HMODULE hLibName = LoadLibraryA(dll_name);
        if (!hLibName) {
            fputs("LoadLibraryA failed\n", stderr);
        }

        for (;;) {
            char key[128] = {0};
            char val[128] = {0};
            if (!cmd_read(fhRead, key, sizeof(key), val, sizeof(val))) {
                break;
            }
            printf("%s -> %s\n", key, val);

            if (!strcmp(key, "SS_I_MEM_FREE")) {
                uintptr_t addr = strtoull(val, NULL, 16);
                if (addr) {
                    if (!VirtualFree((LPVOID)addr, 0, MEM_RELEASE)) {
                        fputs("VirtualFree() failed\n", stderr);
                    }
                }
                continue;
            }

            if (!strcmp(key, "SS_I_ENTRY") || !strcmp(key, "SS_I_TID")) {
                SetEnvironmentVariableA(key, val);
            }

            if (!strcmp(key, "SS_I_END")) {
                // disable restore
                //cmd_write(fhWrite, "SS_S_RESTORE", "0");
                // disable resume
                cmd_write(fhWrite, "SS_S_RESUME", "0");
                cmd_write(fhWrite, "_END", "");
                continue;
            }

            if (!strcmp(key, "_END")) {
                break;
            }
        }
    } while (false);

    if (fhWrite) fclose(fhWrite);
    if (fhRead) fclose(fhRead);
    if (fdWrite >= 0) close(fdWrite);
    if (fdRead >= 0) close(fdRead);
    if (hPipeWrite) CloseHandle(hPipeWrite);
    if (hPipeRead) CloseHandle(hPipeRead);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,
    DWORD fdwReason,
    LPVOID lpvReserved
) {
    switch(fdwReason) {
        case DLL_PROCESS_ATTACH:
            dll_main();
            break;
        default:
            break;
    }
    return TRUE;
}
