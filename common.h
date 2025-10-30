#include <stdbool.h>
#include <stdlib.h>
#include <minwindef.h>
#include <ctype.h>

#define VAR_EXE_NAME "SS_EXE_NAME"
#define VAR_EXE_ENTRY "SS_EXE_ENTRY"
#define VAR_DLL_NAME "SS_DLL_NAME"
#define VAR_RESUME_THREAD "SS_RESUME_THREAD"
// internal
#define VAR_PIPE_HANDLE_READ "SS_PIPE_HANDLE_READ"
#define VAR_PIPE_HANDLE_WRITE "SS_PIPE_HANDLE_WRITE"

static bool parse_var_str(const char *name, char **out)
{
    if(!name || !out) return false;
    *out = getenv(name);
    return *out != NULL;
}

static bool parse_var_ptr(const char *name, LPVOID *out)
{
    if(!name || !out) return false;
    char *v = getenv(name);
    if(!v) return false;
    *(uintptr_t *)out = strtoull(v, NULL, 16);
    return true;
}

static bool cmd_write(FILE *handle, const char *key, const char *val) {
    fprintf(handle, "%s=%s\n", key, val);
    return true;
}

static bool cmd_read(FILE *handle, char *key, size_t key_size, char *val, size_t val_size) {
    char buf[256] = {0};

    if (!fgets(buf, sizeof(buf), handle)) {
        return false;
    }

    buf[strcspn(buf, "\n")] = '\0';

    char *eq = strchr(buf, '=');
    if (!eq) {
        return false;
    }

    *eq = '\0';
    const char *k = buf;
    const char *v = eq + 1;

    strncpy(key, k, key_size - 1);
    key[key_size - 1] = '\0';

    strncpy(val, v, val_size - 1);
    val[val_size - 1] = '\0';

    return true;
}

static void bytes_to_hex(const unsigned char *bytes, size_t bytes_len, char *hex_str, size_t hex_str_len) {
    if (hex_str_len < (bytes_len * 2 + 1)) {
        // Ensure the output buffer is large enough.
        return;
    }

    for (size_t i = 0; i < bytes_len; ++i) {
        sprintf(hex_str + (i * 2), "%02x", bytes[i]);
    }
    // Null-terminate the string.
    hex_str[bytes_len * 2] = '\0';
}

static size_t hex_to_bytes(const char *hex_str, unsigned char *bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || bytes_len < hex_len / 2) {
        return 0;
    }

    size_t num_bytes = hex_len / 2;
    for (size_t i = 0; i < num_bytes; ++i) {
        sscanf(hex_str + (i * 2), "%2hhx", &bytes[i]);
    }

    return num_bytes;
}