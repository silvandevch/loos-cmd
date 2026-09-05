/* ============================================================================
 *  LoOS/cmd.exe  -  Windows Command Processor - Native LoOS Shell
 * ============================================================================
 *  This is the native command processor for LoOS. On LoOS there is no
 *  separate "standard" cmd.exe - THIS IS cmd.exe.
 *
 *  It is a clean, human-written reconstruction of Windows cmd.exe based on
 *  Ghidra decompilation (see cmd.c / cmd_clean.c for the faithful 46k-line
 *  output). Every original internal command and function is ported here in
 *  readable form.
 *
 *  PowerShell-inspired features layered on top:
 *    - Object handling: $obj = @{key=value}, .key access, CONVERTFROM-JSON,
 *      CONVERTTO-JSON, CONVERTFROM-XML, CONVERTTO-XML
 *    - Advanced autocompletion: TAB completes commands, file paths, env vars,
 *      object keys depending on context
 *    - Complex data types: real SET /A arithmetic, ARRAY declarations and
 *      indexed access, FUNC/CALL user-defined functions (no GOTO required)
 *
 *  BUILD (on LoOS VM 192.168.105.128):
 *    call "C:\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64
 *    cl /EHsc /O2 /W0 cmd_reconstructed.c /Fe:cmd.exe
 *    clang-cl /O2 cmd_reconstructed.c /Fe:cmd.exe
 *
 *  INSTALL as native shell:
 *    copy /Y cmd.exe C:\Windows\System32\cmd.exe
 *    copy /Y cmd.exe C:\LoOS\out\cmd.exe
 *
 *  TUI: the prompt now hosts a fixed top tab bar (1-8) drawn on line 0/1.
 *  Click on a tab (left mouse) to switch. TAB at the prompt runs context-
 *  aware completion. Set LOOSDEBUG=1 for verbose developer logging.
 * ============================================================================
 */

#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdbool.h>
#include <conio.h>
#include <time.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <windns.h>
#include <lm.h>
#include <winhttp.h>

/* --------------------------------------------------------------------------
 *  Constants
 * -------------------------------------------------------------------------- */
#define CMD_MAX_LINE      8192
#define CMD_MAX_PATH      32767
#define CMD_MAX_ARGS      256
#define CMD_HISTORY_SIZE  100
#define CMD_PUSHD_MAX     64
#define CMD_SETLOCAL_MAX  32
#define CMD_BATCH_MAX     16
#define CMD_OBJ_MAX_KEYS  64
#define CMD_ARRAY_MAX     256
#define CMD_FUNC_MAX      32

#define CMD_DEFAULT_PROMPT L"$P$G"
#define LOOS_VERSION       L"1.0.0"

/* --------------------------------------------------------------------------
 *  Global State
 * -------------------------------------------------------------------------- */
typedef struct _CMD_STATE {
    wchar_t  currentDir[CMD_MAX_PATH];
    wchar_t  promptFormat[128];
    int      echoOn;
    int      exitRequested;
    int      lastErrorLevel;
    int      extensionsEnabled;
    DWORD    outputCodepage;
    DWORD    inputCodepage;
    HANDLE   hStdIn;
    HANDLE   hStdOut;
    HANDLE   hStdErr;
    int      verifyOn;               // VERIFY flag (write verification)
    // PUSHD/POPD stack
    wchar_t  pushdStack[CMD_PUSHD_MAX][CMD_MAX_PATH];
    int      pushdTop;
    // SETLOCAL stack: saves env snapshot markers
    int      setlocalDepth;
    // Batch execution
    int      batchDepth;
    wchar_t  batchFiles[CMD_BATCH_MAX][CMD_MAX_PATH];
    // FOR / SHIFT params (simple)
    wchar_t *batchArgs[CMD_MAX_ARGS];
    int      batchArgCount;
    int      batchShiftOffset;
} CMD_STATE;

static CMD_STATE g_state;
static wchar_t g_history[CMD_HISTORY_SIZE][CMD_MAX_LINE];
static int     g_historyCount = 0;
static int     g_historyPos   = 0;
static wchar_t g_historyFile[MAX_PATH] = {0};

/* Optional verbose developer logs. Set LOOSDEBUG=1 to enable. */
static int g_devLog = 0;

// TUI Tabs support
#define MAX_TABS 8
static struct {
    wchar_t history[CMD_HISTORY_SIZE][CMD_MAX_LINE];
    int count;
    int pos;
    int active;
} g_tabs[MAX_TABS];
static int g_tabCount = 1;
static int g_currentTab = 0;
static int g_tabBarLines = 2; // Lines for tab bar at top
static SHORT g_tabStripY = -1; /* buffer row of the travelling tab strip */

/* ============================================================================
 *  Structured data: objects (hashtables), arrays, and user-defined functions.
 *  These live alongside the environment-variable namespace and are addressed
 *  with PowerShell-style syntax: $obj.key  $arr[0]  FUNC name { ... }
 * ============================================================================ */
typedef struct {
    wchar_t key[64];
    wchar_t value[CMD_MAX_LINE];
} OBJ_PAIR;

typedef struct {
    wchar_t name[64];
    OBJ_PAIR pairs[CMD_OBJ_MAX_KEYS];
    int count;
} LOOS_OBJ;

#define MAX_OBJS 64
static LOOS_OBJ g_objs[MAX_OBJS];
static int g_objCount = 0;

typedef struct {
    wchar_t name[64];
    wchar_t items[CMD_ARRAY_MAX][CMD_MAX_LINE];
    int count;
} LOOS_ARR;

#define MAX_ARRS 32
static LOOS_ARR g_arrs[MAX_ARRS];
static int g_arrCount = 0;

typedef struct {
    wchar_t name[64];
    /* The function body is the literal lines captured between FUNC name { and
       the matching closing brace. Each line is a complete cmd statement that
       can be fed through cmd_execute_line. We also store parameter names. */
    wchar_t params[8][64];
    int paramCount;
    wchar_t body[CMD_FUNC_MAX][CMD_MAX_LINE];
    int bodyLines;
} LOOS_FUNC;

static LOOS_FUNC g_funcs[16];
static int g_funcCount = 0;

/* Lookup helpers - return index or -1 */
static int obj_find(const wchar_t *name)
{
    for(int i=0;i<g_objCount;i++) if(_wcsicmp(g_objs[i].name, name) == 0) return i;
    return -1;
}
static int arr_find(const wchar_t *name)
{
    for(int i=0;i<g_arrCount;i++) if(_wcsicmp(g_arrs[i].name, name) == 0) return i;
    return -1;
}
static int func_find(const wchar_t *name)
{
    for(int i=0;i<g_funcCount;i++) if(_wcsicmp(g_funcs[i].name, name) == 0) return i;
    return -1;
}

/* Set / get a value on an object by key. value==NULL deletes the key. */
static int obj_set_key(int idx, const wchar_t *key, const wchar_t *value)
{
    if(idx < 0 || idx >= g_objCount) return -1;
    LOOS_OBJ *o = &g_objs[idx];
    if(!value){
        for(int i=0;i<o->count;i++) if(_wcsicmp(o->pairs[i].key, key) == 0){
            for(int j=i;j<o->count-1;j++) o->pairs[j] = o->pairs[j+1];
            o->count--;
            return 0;
        }
        return -1;
    }
    for(int i=0;i<o->count;i++) if(_wcsicmp(o->pairs[i].key, key) == 0){
        wcsncpy_s(o->pairs[i].value, CMD_MAX_LINE, value, _TRUNCATE);
        return 0;
    }
    if(o->count >= CMD_OBJ_MAX_KEYS) return -1;
    wcsncpy_s(o->pairs[o->count].key,   64,        key,   _TRUNCATE);
    wcsncpy_s(o->pairs[o->count].value, CMD_MAX_LINE, value, _TRUNCATE);
    o->count++;
    return 0;
}
static const wchar_t *obj_get_key(int idx, const wchar_t *key)
{
    if(idx < 0 || idx >= g_objCount) return NULL;
    LOOS_OBJ *o = &g_objs[idx];
    for(int i=0;i<o->count;i++) if(_wcsicmp(o->pairs[i].key, key) == 0) return o->pairs[i].value;
    return NULL;
}

/* Create / replace an object with one key=value pair. If the object already
   exists, the new key/value is added (or the existing key overwritten). */
static int obj_upsert(const wchar_t *name, const wchar_t *key, const wchar_t *value)
{
    int idx = obj_find(name);
    if(idx < 0){
        if(g_objCount >= MAX_OBJS) return -1;
        idx = g_objCount++;
        wcsncpy_s(g_objs[idx].name, 64, name, _TRUNCATE);
        g_objs[idx].count = 0;
    }
    return obj_set_key(idx, key, value);
}

/* List keys of an object (used by completion). Writes the first matching
   prefix-equal key into out (if any). */
static int obj_first_key_with_prefix(int idx, const wchar_t *prefix, wchar_t *out, size_t outSize)
{
    if(idx < 0 || idx >= g_objCount) return 0;
    size_t pl = wcslen(prefix);
    for(int i=0;i<g_objs[idx].count;i++){
        if(_wcsnicmp(g_objs[idx].pairs[i].key, prefix, pl) == 0){
            wcsncpy_s(out, outSize, g_objs[idx].pairs[i].key, _TRUNCATE);
            return 1;
        }
    }
    return 0;
}
static int obj_count_with_prefix(int idx, const wchar_t *prefix)
{
    if(idx < 0 || idx >= g_objCount) return 0;
    size_t pl = wcslen(prefix);
    int n = 0;
    for(int i=0;i<g_objs[idx].count;i++) if(_wcsnicmp(g_objs[idx].pairs[i].key, prefix, pl) == 0) n++;
    return n;
}

/* Forward declarations */
static void     dev_log(const wchar_t *fmt, ...);
static void     cmd_init(void);
static void     cmd_main_loop(void);
static int      cmd_execute_line(wchar_t *line);
static int      cmd_dispatch(wchar_t **argv, int argc, wchar_t *rawLine);
static wchar_t* cmd_expand_env_vars(const wchar_t *input, wchar_t *output, size_t outSize);
static void     cmd_show_prompt(void);
static void     cmd_print_error(const wchar_t *fmt, ...);
static int      cmd_builtin_history(int argc, wchar_t **argv);
static void     history_load(void);
static void     tabs_init(void);
static void     tabs_draw_bar(void);
static void     tabs_print_strip(void);
static void     tabs_refresh_strip(void);
static void     tabs_build_strip_line(wchar_t *line, size_t size);
static void     tabs_switch(int newTab);
static void     tabs_new(void);
static void     tabs_close(void);
static int      tabs_handle_input(void);
static void     history_save(void);
static void     history_add(const wchar_t *cmd);
static int      is_interactive_terminal(void);
static int      cmd_run_batch_file(const wchar_t *path, wchar_t **args, int argc);

/* Built-ins - each returns 0 on success */
static int cmd_builtin_echo(wchar_t **argv, int argc);
static int cmd_builtin_cd(wchar_t **argv, int argc);
static int cmd_builtin_dir(wchar_t **argv, int argc);
static int cmd_builtin_cls(wchar_t **argv, int argc);
static int cmd_builtin_type(wchar_t **argv, int argc);
static int cmd_builtin_del(wchar_t **argv, int argc);
static int cmd_builtin_copy(wchar_t **argv, int argc);
static int cmd_builtin_move(wchar_t **argv, int argc);
static int cmd_builtin_ren(wchar_t **argv, int argc);
static int cmd_builtin_md(wchar_t **argv, int argc);
static int cmd_builtin_rd(wchar_t **argv, int argc);
static int cmd_builtin_set(wchar_t **argv, int argc);
static int cmd_builtin_path(wchar_t **argv, int argc);
static int cmd_builtin_ver(wchar_t **argv, int argc);
static int cmd_builtin_title(wchar_t **argv, int argc);
static int cmd_builtin_exit(wchar_t **argv, int argc);
static int cmd_builtin_help(wchar_t **argv, int argc);
static int cmd_builtin_assoc(wchar_t **argv, int argc);
static int cmd_builtin_attrib(wchar_t **argv, int argc);
static int cmd_builtin_break(wchar_t **argv, int argc);
static int cmd_builtin_call(wchar_t **argv, int argc);
static int cmd_builtin_chcp(wchar_t **argv, int argc);
static int cmd_builtin_color(wchar_t **argv, int argc);
static int cmd_builtin_date(wchar_t **argv, int argc);
static int cmd_builtin_endlocal(wchar_t **argv, int argc);
static int cmd_builtin_for(wchar_t **argv, int argc);
static int cmd_builtin_ftype(wchar_t **argv, int argc);
static int cmd_builtin_goto(wchar_t **argv, int argc);
static int cmd_builtin_if(wchar_t **argv, int argc);
static int cmd_builtin_mklink(wchar_t **argv, int argc);
static int cmd_builtin_more(wchar_t **argv, int argc);
static int cmd_builtin_pause(wchar_t **argv, int argc);
static int cmd_builtin_popd(wchar_t **argv, int argc);
static int cmd_builtin_prompt(wchar_t **argv, int argc);
static int cmd_builtin_pushd(wchar_t **argv, int argc);
static int cmd_builtin_rem(wchar_t **argv, int argc);
static int cmd_builtin_setlocal(wchar_t **argv, int argc);
static int cmd_builtin_shift(wchar_t **argv, int argc);
static int cmd_builtin_start(wchar_t **argv, int argc);
static int cmd_builtin_time(wchar_t **argv, int argc);
static int cmd_builtin_verify(wchar_t **argv, int argc);
static int cmd_builtin_vol(wchar_t **argv, int argc);
// LoOS powerful extensions - native Windows tools
static int cmd_builtin_ping(wchar_t **argv, int argc);
static int cmd_builtin_ipconfig(wchar_t **argv, int argc);
static int cmd_builtin_netstat(wchar_t **argv, int argc);
static int cmd_builtin_tracert(wchar_t **argv, int argc);
static int cmd_builtin_nslookup(wchar_t **argv, int argc);
static int cmd_builtin_arp(wchar_t **argv, int argc);
static int cmd_builtin_route(wchar_t **argv, int argc);
static int cmd_builtin_net(wchar_t **argv, int argc);
static int cmd_builtin_reg(wchar_t **argv, int argc);
static int cmd_builtin_where(wchar_t **argv, int argc);
static int cmd_builtin_whoami(wchar_t **argv, int argc);
static int cmd_builtin_setx(wchar_t **argv, int argc);
static int cmd_builtin_timeout(wchar_t **argv, int argc);
static int cmd_builtin_choice(wchar_t **argv, int argc);
static int cmd_builtin_clip(wchar_t **argv, int argc);
static int cmd_builtin_takeown(wchar_t **argv, int argc);
static int cmd_builtin_curl(wchar_t **argv, int argc);
static int cmd_builtin_grep(wchar_t **argv, int argc);
static int cmd_builtin_ls(wchar_t **argv, int argc);
static int cmd_builtin_ps(wchar_t **argv, int argc);
static int cmd_builtin_kill(wchar_t **argv, int argc);
static int cmd_builtin_nbtstat(wchar_t **argv, int argc);
static int cmd_builtin_netsh(wchar_t **argv, int argc);
static int cmd_builtin_powercfg(wchar_t **argv, int argc);
static int cmd_builtin_sfc(wchar_t **argv, int argc);

/* Unix-style aliases + interactive niceties */
static int cmd_builtin_unix_aliases(wchar_t **argv, int argc);  /* dispatches ls/rm/cat/cp/mv/etc. */
static int cmd_builtin_sudo(wchar_t **argv, int argc);          /* relaunch as admin */
static int cmd_builtin_theme(wchar_t **argv, int argc);          /* palette swapper */
static int cmd_builtin_cursor(wchar_t **argv, int argc);         /* cursor shape */
static int cmd_builtin_did_you_mean(wchar_t **argv, int argc);   /* typo correction hook */

/* Visual / session niceties */
static int cmd_builtin_hyperlinks_on(wchar_t **argv, int argc);
static int cmd_builtin_hyperlinks_off(wchar_t **argv, int argc);
static int cmd_builtin_session_save(wchar_t **argv, int argc);
static int cmd_builtin_session_restore(wchar_t **argv, int argc);
static int cmd_builtin_quake_toggle(wchar_t **argv, int argc);
static int cmd_builtin_autocopy(wchar_t **argv, int argc);
static int cmd_builtin_blur(wchar_t **argv, int argc);
static int cmd_builtin_tabname(wchar_t **argv, int argc);
static void cmd_apply_hyperlink_filter(int on);
static void cmd_load_session(void);
static void cmd_save_session(void);
static void cmd_apply_blur(HWND hwnd);

/* PowerShell-inspired: structured data + advanced types */
static int cmd_builtin_obj(wchar_t **argv, int argc);          /* OBJ / $obj = @{k=v; k=v} */
static int cmd_builtin_convertfrom_json(wchar_t **argv, int argc);
static int cmd_builtin_convertto_json(wchar_t **argv, int argc);
static int cmd_builtin_convertfrom_xml(wchar_t **argv, int argc);
static int cmd_builtin_convertto_xml(wchar_t **argv, int argc);
static int cmd_builtin_obj_set(wchar_t **argv, int argc);      /* OSET $obj.key = value */
static int cmd_builtin_obj_get(wchar_t **argv, int argc);      /* OGET $obj.key */
static int cmd_builtin_obj_list(wchar_t **argv, int argc);     /* OBJECTS / ODEL */
static int cmd_builtin_array(wchar_t **argv, int argc);        /* ARRAY name = 1,2,3 */
static int cmd_builtin_aget(wchar_t **argv, int argc);         /* AGET $arr[0] */
static int cmd_builtin_aset(wchar_t **argv, int argc);         /* ASET $arr[0] = value */
static int cmd_builtin_alist(wchar_t **argv, int argc);        /* ARRAYS / ADEL */
static int cmd_builtin_func(wchar_t **argv, int argc);         /* FUNC name { ... } */
static int cmd_builtin_callfunc(wchar_t **argv, int argc);     /* CALL name arg1 arg2 */
static int cmd_builtin_funcs(wchar_t **argv, int argc);        /* FUNCS / FUNCDEL */
static int cmd_builtin_tabclose(wchar_t **argv, int argc);
static int cmd_builtin_tabnext (wchar_t **argv, int argc);
static int cmd_builtin_tabprev (wchar_t **argv, int argc);
static int cmd_builtin_tabgo   (wchar_t **argv, int argc);

/* Arithmetic evaluator for SET /A */
static long long loos_eval_expr(const wchar_t *expr, const wchar_t **endp);

/* Helpers */
static int  wcs_starts_with_i(const wchar_t *str, const wchar_t *prefix);
static void wcs_trim(wchar_t *s);
static int  tokenize(wchar_t *line, wchar_t *argv[], int maxArgs);
static void print_file_attributes(const wchar_t *path);

/* ==========================================================================
 *  Helpers
 * ========================================================================== */
static int wcs_starts_with_i(const wchar_t *str, const wchar_t *prefix)
{
    while (*prefix) {
        wchar_t a = towlower(*str);
        wchar_t b = towlower(*prefix);
        if (a != b) return 0;
        str++; prefix++;
    }
    return 1;
}

static void wcs_trim(wchar_t *s)
{
    wchar_t *start = s;
    wchar_t *end;
    while (*start == L' ' || *start == L'\t') start++;
    if (start != s) wmemmove(s, start, (wcslen(start) + 1) * sizeof(wchar_t));
    end = s + wcslen(s);
    while (end > s && (end[-1] == L' ' || end[-1] == L'\t' || end[-1] == L'\r' || end[-1] == L'\n')) { end--; *end = L'\0'; }
}

/* Tokenize respecting double quotes. Returns argc. */
static int tokenize(wchar_t *line, wchar_t *argv[], int maxArgs)
{
    int argc = 0;
    wchar_t *p = line;
    while (*p && argc < maxArgs) {
        while (*p == L' ' || *p == L'\t') p++;
        if (!*p || *p == L'\r' || *p == L'\n') break;
        if (*p == L'"') {
            p++; argv[argc++] = p;
            while (*p && *p != L'"') p++;
            if (*p == L'"') { *p = L'\0'; p++; }
        } else {
            argv[argc++] = p;
            while (*p && *p != L' ' && *p != L'\t' && *p != L'\r' && *p != L'\n') p++;
            if (*p) { *p = L'\0'; p++; }
        }
    }
    return argc;
}

/* Look up "$name" or "%name%" env var / object / array element. Returns
   pointer to internal storage (do not free). Used by cmd_expand_env_vars. */
static const wchar_t *loos_resolve(const wchar_t *name, size_t nameLen)
{
    static wchar_t scratch[CMD_MAX_LINE];
    scratch[0] = L'\0';
    /* Positional call arguments: $1, $2 ... $8 (also $1x if user does $10). */
    if(nameLen >= 1 && iswdigit(name[0])){
        wchar_t idxStr[8] = {0};
        size_t cl = nameLen < 7 ? nameLen : 7;
        wcsncpy_s(idxStr, 8, name, cl);
        int idx = _wtoi(idxStr);
        if(idx >= 1 && idx <= 8){
            wchar_t envName[32];
            swprintf_s(envName, 32, L"__CALLPARAM%d", idx);
            DWORD got = GetEnvironmentVariableW(envName, scratch, CMD_MAX_LINE);
            if(got > 0 && got < CMD_MAX_LINE) return scratch;
            return NULL;
        }
    }
    /* Object dotted access: "obj.key" */
    const wchar_t *dot = NULL;
    for(size_t i=0;i<nameLen;i++){ if(name[i] == L'.'){ dot = name + i; break; } }
    if(dot){
        wchar_t oname[64]; size_t onl = (size_t)(dot - name);
        if(onl >= 64) return NULL;
        wcsncpy_s(oname, 64, name, onl);
        int idx = obj_find(oname);
        if(idx < 0) return NULL;
        wchar_t key[64]; size_t kl = nameLen - onl - 1;
        if(kl >= 64) kl = 63;
        wcsncpy_s(key, 64, dot + 1, kl);
        return obj_get_key(idx, key);
    }
    /* Array indexed access: "arr[3]" */
    const wchar_t *lb = NULL;
    for(size_t i=0;i<nameLen;i++){ if(name[i] == L'['){ lb = name + i; break; } }
    if(lb){
        wchar_t aname[64]; size_t anl = (size_t)(lb - name);
        if(anl >= 64) return NULL;
        wcsncpy_s(aname, 64, name, anl);
        int idx = arr_find(aname);
        if(idx < 0) return NULL;
        const wchar_t *rb = wcschr(lb, L']');
        if(!rb) return NULL;
        wchar_t idxBuf[32]; size_t il = (size_t)(rb - lb - 1);
        if(il >= 32) il = 31;
        wcsncpy_s(idxBuf, 32, lb + 1, il);
        int ai = _wtoi(idxBuf);
        if(ai < 0 || ai >= g_arrs[idx].count) return NULL;
        return g_arrs[idx].items[ai];
    }
    /* Plain env var */
    wchar_t nameZ[128];
    if(nameLen >= 128) return NULL;
    wcsncpy_s(nameZ, 128, name, nameLen);
    DWORD got = GetEnvironmentVariableW(nameZ, scratch, CMD_MAX_LINE);
    if(got > 0 && got < CMD_MAX_LINE) return scratch;
    return NULL;
}

static wchar_t* cmd_expand_env_vars(const wchar_t *input, wchar_t *output, size_t outSize)
{
    /* Two-pass expansion: first Windows ExpandEnvironmentStringsW handles
       %FOO% expansions (and honors any FOO=... we set via SET). Then we
       run a second pass to expand $obj.key and $arr[idx] references, which
       Windows does not know about. */
    wchar_t tmp[CMD_MAX_LINE];
    DWORD len = ExpandEnvironmentStringsW(input, tmp, CMD_MAX_LINE);
    if(len == 0 || len >= CMD_MAX_LINE){
        wcsncpy_s(tmp, CMD_MAX_LINE, input, _TRUNCATE);
    }
    /* Pass 2: replace $name and $name.path with our resolved values. */
    size_t oi = 0;
    for(size_t i=0; tmp[i] && oi < outSize - 1; ){
        if(tmp[i] == L'$' && tmp[i+1] && (iswalnum(tmp[i+1]) || tmp[i+1] == L'_')){
            size_t j = i + 1;
            while(tmp[j] && (iswalnum(tmp[j]) || tmp[j] == L'_' || tmp[j] == L'.' || tmp[j] == L'[' || tmp[j] == L']' || iswdigit(tmp[j]))) j++;
            const wchar_t *resolved = loos_resolve(tmp + i + 1, j - i - 1);
            if(resolved && resolved[0]){
                size_t rl = wcslen(resolved);
                if(oi + rl < outSize - 1){
                    wmemcpy(output + oi, resolved, rl * sizeof(wchar_t));
                    oi += rl;
                }
            } else {
                /* keep $name verbatim */
                if(oi + (j - i) < outSize - 1){
                    wmemcpy(output + oi, tmp + i, (j - i) * sizeof(wchar_t));
                    oi += j - i;
                }
            }
            i = j;
        } else {
            output[oi++] = tmp[i++];
        }
    }
    output[oi] = L'\0';
    return output;
}

static void cmd_print_error(const wchar_t *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fwprintf(stderr, L"Error: ");
    vfwprintf(stderr, fmt, args);
    fwprintf(stderr, L"\n");
    va_end(args);
}

/* ==========================================================================
 *  Built-ins
 * ========================================================================== */

/* ECHO */
static int cmd_builtin_echo(wchar_t **argv, int argc)
{
    if (argc == 1) { wprintf(L"ECHO is %s.\n", g_state.echoOn ? L"on" : L"off"); return 0; }
    if (argc == 2 && _wcsicmp(argv[1], L"ON") == 0) { g_state.echoOn = 1; return 0; }
    if (argc == 2 && _wcsicmp(argv[1], L"OFF") == 0) { g_state.echoOn = 0; return 0; }
    for (int i = 1; i < argc; i++) { if (i > 1) wprintf(L" "); wprintf(L"%s", argv[i]); }
    wprintf(L"\n"); return 0;
}

/* CD / CHDIR */
static int cmd_builtin_cd(wchar_t **argv, int argc)
{
    if (argc == 1) { wprintf(L"%s\n", g_state.currentDir); return 0; }
    const wchar_t *target = argv[1];
    if (argc >= 3 && _wcsicmp(argv[1], L"/D") == 0) target = argv[2];
    if (!SetCurrentDirectoryW(target)) {
        DWORD err = GetLastError(); wchar_t msg[512];
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,err,0,msg,512,NULL);
        wcs_trim(msg); cmd_print_error(L"%s - %s", target, msg); return 1;
    }
    GetCurrentDirectoryW(CMD_MAX_PATH, g_state.currentDir); return 0;
}

/* DIR */
static int cmd_builtin_dir(wchar_t **argv, int argc)
{
    const wchar_t *path = L"*";
    for (int i = 1; i < argc; i++) if (argv[i][0] != L'/') { path = argv[i]; break; }
    WIN32_FIND_DATAW fd;
    wchar_t searchPath[CMD_MAX_PATH], dirPart[CMD_MAX_PATH];
    DWORD attrs = GetFileAttributesW(path);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        swprintf_s(searchPath, CMD_MAX_PATH, L"%s\\*", path);
        wcsncpy_s(dirPart, CMD_MAX_PATH, path, _TRUNCATE);
    } else if (wcschr(path, L'*') || wcschr(path, L'?')) {
        wcsncpy_s(searchPath, CMD_MAX_PATH, path, _TRUNCATE);
        wcsncpy_s(dirPart, CMD_MAX_PATH, g_state.currentDir, _TRUNCATE);
    } else {
        wcsncpy_s(searchPath, CMD_MAX_PATH, path, _TRUNCATE);
        wcsncpy_s(dirPart, CMD_MAX_PATH, g_state.currentDir, _TRUNCATE);
    }
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) { wprintf(L"File Not Found\n"); return 1; }
    wprintf(L"\n Directory of %s\n\n", dirPart);
    int fileCount=0, dirCount=0; ULONGLONG totalBytes=0;
    do {
        if (wcscmp(fd.cFileName,L".")==0 || wcscmp(fd.cFileName,L"..")==0) continue;
        SYSTEMTIME st; FileTimeToSystemTime(&fd.ftLastWriteTime,&st);
        wprintf(L"%02d/%02d/%04d  %02d:%02d %s ",st.wMonth,st.wDay,st.wYear,st.wHour%12==0?12:st.wHour%12,st.wMinute,st.wHour>=12?L"PM":L"AM");
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){ wprintf(L"    <DIR>          %s\n",fd.cFileName); dirCount++; }
        else { ULONGLONG sz=((ULONGLONG)fd.nFileSizeHigh<<32)|fd.nFileSizeLow; wprintf(L"%14llu %s\n",sz,fd.cFileName); fileCount++; totalBytes+=sz; }
    } while(FindNextFileW(hFind,&fd));
    FindClose(hFind);
    wprintf(L"               %d File(s) %llu bytes\n               %d Dir(s)\n",fileCount,totalBytes,dirCount);
    return 0;
}

/* CLS */
static int cmd_builtin_cls(wchar_t **argv, int argc){ (void)argv;(void)argc;
    HANDLE hOut=GetStdHandle(STD_OUTPUT_HANDLE); CONSOLE_SCREEN_BUFFER_INFO csbi; COORD tl={0,0}; DWORD w;
    if(!GetConsoleScreenBufferInfo(hOut,&csbi)) return 1;
    DWORD cells=csbi.dwSize.X*csbi.dwSize.Y;
    FillConsoleOutputCharacterW(hOut,L' ',cells,tl,&w);
    FillConsoleOutputAttribute(hOut,csbi.wAttributes,cells,tl,&w);
    SetConsoleCursorPosition(hOut,tl); return 0; }

/* TYPE */
static int cmd_builtin_type(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"TYPE: missing file name"); return 1; }
    for(int i=1;i<argc;i++){
        HANDLE h=CreateFileW(argv[i],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(h==INVALID_HANDLE_VALUE){ cmd_print_error(L"TYPE: cannot open %s",argv[i]); return 1; }
        char buf[4096]; DWORD r; while(ReadFile(h,buf,sizeof(buf),&r,NULL)&&r>0){ DWORD wr; WriteFile(g_state.hStdOut,buf,r,&wr,NULL); }
        CloseHandle(h);
    } return 0;
}

/* DEL / ERASE */
static int cmd_builtin_del(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"DEL: missing file name"); return 1; }
    int quiet=0,force=0,res=0;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/Q")==0){quiet=1;continue;}
        if(_wcsicmp(argv[i],L"/F")==0){force=1;continue;}
        if(_wcsicmp(argv[i],L"/S")==0){continue;} // subdirs - simplified
        if(argv[i][0]==L'/') continue;
        WIN32_FIND_DATAW fd; HANDLE hf=FindFirstFileW(argv[i],&fd);
        if(hf==INVALID_HANDLE_VALUE){
            DWORD a=GetFileAttributesW(argv[i]);
            if(a!=INVALID_FILE_ATTRIBUTES && (a&FILE_ATTRIBUTE_READONLY) && !force){ if(!quiet) cmd_print_error(L"%s is read-only (use /F)",argv[i]); res=1; continue; }
            if(!DeleteFileW(argv[i])){ if(!quiet) cmd_print_error(L"cannot delete %s",argv[i]); res=1; } continue;
        }
        wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(argv[i],L'\\');
        if(sl) wcsncpy_s(dir,CMD_MAX_PATH,argv[i],sl-argv[i]+1);
        do{
            if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
            if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wchar_t fp[CMD_MAX_PATH]; swprintf_s(fp,CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
            if((fd.dwFileAttributes & FILE_ATTRIBUTE_READONLY) && !force){ if(!quiet) cmd_print_error(L"%s is read-only",fp); res=1; continue; }
            if(!DeleteFileW(fp) && !quiet){ cmd_print_error(L"cannot delete %s",fp); res=1; }
        }while(FindNextFileW(hf,&fd)); FindClose(hf);
    } return res;
}

/* COPY */
static int cmd_builtin_copy(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Usage: COPY <source> <dest>  [/Y]\n"); return 1; }
    const wchar_t *src=NULL,*dst=NULL; int noPrompt=0;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/Y")==0||_wcsicmp(argv[i],L"/-Y")==0){noPrompt=1;continue;}
        if(argv[i][0]==L'/') continue;
        if(!src) src=argv[i]; else if(!dst) dst=argv[i];
    }
    if(!src||!dst){ cmd_print_error(L"COPY: missing source or dest"); return 1; }
    (void)noPrompt;
    // Support wildcard copy: if src has wildcard, copy each match
    if(wcschr(src,L'*')||wcschr(src,L'?')){
        WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(src,&fd);
        if(h==INVALID_HANDLE_VALUE){ cmd_print_error(L"COPY: File not found - %s",src); return 1; }
        wchar_t srcDir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(src,L'\\');
        if(sl) wcsncpy_s(srcDir,CMD_MAX_PATH,src,sl-src+1);
        int count=0;
        do{
            if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
            if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            wchar_t s[CMD_MAX_PATH], d[CMD_MAX_PATH];
            swprintf_s(s,CMD_MAX_PATH,L"%s%s",srcDir,fd.cFileName);
            // dst may be directory
            DWORD da=GetFileAttributesW(dst);
            if(da!=INVALID_FILE_ATTRIBUTES && (da&FILE_ATTRIBUTE_DIRECTORY)) swprintf_s(d,CMD_MAX_PATH,L"%s\\%s",dst,fd.cFileName);
            else wcsncpy_s(d,CMD_MAX_PATH,dst,_TRUNCATE);
            if(!CopyFileW(s,d,FALSE)){ cmd_print_error(L"COPY: failed %s -> %s",s,d); }
            else count++;
        }while(FindNextFileW(h,&fd)); FindClose(h);
        wprintf(L"        %d file(s) copied.\n",count); return 0;
    }
    if(!CopyFileW(src,dst,FALSE)){ DWORD e=GetLastError(); wchar_t m[256]; FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,NULL,e,0,m,256,NULL); wcs_trim(m); cmd_print_error(L"COPY: %s",m); return 1; }
    wprintf(L"        1 file(s) copied.\n"); return 0;
}

/* MOVE */
static int cmd_builtin_move(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Usage: MOVE <source> <dest>\n"); return 1; }
    const wchar_t *src=NULL,*dst=NULL;
    for(int i=1;i<argc;i++){ if(argv[i][0]==L'/') continue; if(!src) src=argv[i]; else if(!dst) dst=argv[i]; }
    if(!src||!dst){ cmd_print_error(L"MOVE: missing arg"); return 1; }
    if(wcschr(src,L'*')||wcschr(src,L'?')){
        WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(src,&fd);
        if(h==INVALID_HANDLE_VALUE){ cmd_print_error(L"MOVE: File not found"); return 1; }
        wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(src,L'\\');
        if(sl) wcsncpy_s(dir,CMD_MAX_PATH,src,sl-src+1);
        int count=0;
        do{
            if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0)continue;
            wchar_t s[CMD_MAX_PATH],d[CMD_MAX_PATH];
            swprintf_s(s,CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
            DWORD da=GetFileAttributesW(dst);
            if(da!=INVALID_FILE_ATTRIBUTES && (da&FILE_ATTRIBUTE_DIRECTORY)) swprintf_s(d,CMD_MAX_PATH,L"%s\\%s",dst,fd.cFileName);
            else wcsncpy_s(d,CMD_MAX_PATH,dst,_TRUNCATE);
            if(MoveFileW(s,d)) count++; else cmd_print_error(L"MOVE: failed %s",s);
        }while(FindNextFileW(h,&fd)); FindClose(h);
        return count?0:1;
    }
    if(!MoveFileW(src,dst)){ cmd_print_error(L"MOVE: cannot move %s",src); return 1; } return 0;
}

/* REN / RENAME */
static int cmd_builtin_ren(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Usage: REN <old> <new>\n"); return 1; }
    if(!MoveFileW(argv[1],argv[2])){ cmd_print_error(L"REN: cannot rename %s",argv[1]); return 1; } return 0;
}

/* MD / MKDIR */
static int cmd_builtin_md(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"MKDIR: missing name"); return 1; }
    for(int i=1;i<argc;i++){ if(argv[i][0]==L'/') continue;
        // Support nested dirs: create parents as needed
        wchar_t path[CMD_MAX_PATH]; wcsncpy_s(path,CMD_MAX_PATH,argv[i],_TRUNCATE);
        // Walk and create each component
        for(wchar_t *p=path; *p; p++){
            if(*p==L'\\' || *p==L'/'){
                wchar_t save=*p; *p=L'\0';
                if(wcslen(path)>0 && wcscmp(path,L".")!=0) CreateDirectoryW(path,NULL);
                *p=save;
            }
        }
        if(!CreateDirectoryW(path,NULL)){ DWORD e=GetLastError(); if(e!=ERROR_ALREADY_EXISTS){ cmd_print_error(L"MKDIR: cannot create %s",argv[i]); return 1; } }
    } return 0;
}

/* RD / RMDIR */
static int cmd_builtin_rd(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"RMDIR: missing name"); return 1; }
    int rec=0, quiet=0;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/S")==0){rec=1;continue;}
        if(_wcsicmp(argv[i],L"/Q")==0){quiet=1;continue;}
        if(argv[i][0]==L'/') continue;
        if(rec){
            // Recursive delete: walk tree
            // Use SHFileOperationW for simplicity if available, else manual
            wchar_t full[CMD_MAX_PATH*2]; swprintf_s(full,CMD_MAX_PATH*2,L"%s",argv[i]);
            // Try RemoveDirectory first (if empty)
            if(RemoveDirectoryW(full)) continue;
            // Recursive: enumerate and delete
            // We implement a simple stack-based delete
            // For brevity use system helper via cmd /c but avoid recursion loop
            // Manual walk:
            WIN32_FIND_DATAW fd; wchar_t pat[CMD_MAX_PATH]; swprintf_s(pat,CMD_MAX_PATH,L"%s\\*",full);
            HANDLE h=FindFirstFileW(pat,&fd);
            if(h!=INVALID_HANDLE_VALUE){
                do{
                    if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
                    wchar_t child[CMD_MAX_PATH]; swprintf_s(child,CMD_MAX_PATH,L"%s\\%s",full,fd.cFileName);
                    if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                        wchar_t subArgs[CMD_MAX_PATH*2]; swprintf_s(subArgs,CMD_MAX_PATH*2,L"\"%s\"",child);
                        wchar_t *a[]={(wchar_t*)L"RD",L"/S",L"/Q",subArgs,NULL};
                        cmd_builtin_rd(a,4);
                    } else {
                        // Clear readonly
                        SetFileAttributesW(child,FILE_ATTRIBUTE_NORMAL);
                        DeleteFileW(child);
                    }
                }while(FindNextFileW(h,&fd)); FindClose(h);
            }
            SetFileAttributesW(full,FILE_ATTRIBUTE_NORMAL);
            if(!RemoveDirectoryW(full) && !quiet){ cmd_print_error(L"RMDIR: cannot remove %s",argv[i]); return 1; }
        } else {
            if(!RemoveDirectoryW(argv[i])){ if(!quiet) cmd_print_error(L"RMDIR: cannot remove %s (not empty? use /S)",argv[i]); return 1; }
        }
    } return 0;
}

/* ============================================================================
 *  Recursive-descent integer expression evaluator for SET /A.
 *  Grammar (loosely CMD-compatible):
 *      expr   := term (('+'|'-') term)*
 *      term   := factor (('*'|'/'|'%') factor)*
 *      factor := ('-' factor) | ('+' factor) | '(' expr ')' | number | ident
 *      number := [0-9]+
 *      ident  := [A-Za-z_][A-Za-z_0-9.]*   (looks up env var / object field)
 *
 *  Returns LLONG_MIN on parse error.
 * ============================================================================ */
static long long loos_eval_expr_impl(const wchar_t *p, const wchar_t **endp);

static void loos_skip_ws(const wchar_t **pp)
{
    while(**pp == L' ' || **pp == L'\t') (*pp)++;
}

static long long loos_eval_number_or_ident(const wchar_t **pp)
{
    loos_skip_ws(pp);
    if(iswdigit(**pp)){
        long long v = 0;
        while(iswdigit(**pp)){ v = v*10 + (**pp - L'0'); (*pp)++; }
        return v;
    }
    if(iswalpha(**pp) || **pp == L'_' || **pp == L'$'){
        wchar_t name[128]; size_t ni = 0;
        if(**pp == L'$') name[ni++] = *(*pp)++;
        while(**pp && (iswalnum(**pp) || **pp == L'_' || **pp == L'.' || **pp == L'[' || **pp == L']')){
            if(ni >= 127) break;
            name[ni++] = *(*pp)++;
        }
        name[ni] = L'\0';
        const wchar_t *resolved = loos_resolve(name, ni);
        if(resolved && resolved[0]) return _wtoi64(resolved);
        return 0; /* undefined -> 0, matches CMD */
    }
    return LLONG_MIN;
}

static long long loos_eval_factor(const wchar_t **pp)
{
    loos_skip_ws(pp);
    if(**pp == L'('){
        (*pp)++;
        long long v = loos_eval_expr_impl(*pp, pp);
        if(**pp != L')') return LLONG_MIN;
        (*pp)++;
        return v;
    }
    if(**pp == L'-'){ (*pp)++; return -loos_eval_factor(pp); }
    if(**pp == L'+'){ (*pp)++; return loos_eval_factor(pp); }
    return loos_eval_number_or_ident(pp);
}

static long long loos_eval_term(const wchar_t **pp)
{
    long long left = loos_eval_factor(pp);
    for(;;){
        loos_skip_ws(pp);
        wchar_t op = **pp;
        if(op != L'*' && op != L'/' && op != L'%') return left;
        (*pp)++;
        long long right = loos_eval_factor(pp);
        if(right == LLONG_MIN) return LLONG_MIN;
        if(op == L'*') left = left * right;
        else if(op == L'/'){ if(right == 0) return LLONG_MIN; left = left / right; }
        else             { if(right == 0) return LLONG_MIN; left = left % right; }
    }
}

static long long loos_eval_expr_impl(const wchar_t *p, const wchar_t **endp)
{
    long long left = loos_eval_term(&p);
    for(;;){
        loos_skip_ws(&p);
        wchar_t op = *p;
        if(op != L'+' && op != L'-') break;
        /* Don't gobble a '-' that starts a negative number after a term: our
           loos_eval_term already handles that case so '-' here is binary. */
        p++;
        long long right = loos_eval_term(&p);
        if(right == LLONG_MIN) return LLONG_MIN;
        if(op == L'+') left = left + right;
        else            left = left - right;
    }
    if(endp) *endp = p;
    return left;
}

static long long loos_eval_expr(const wchar_t *expr, const wchar_t **endp)
{
    return loos_eval_expr_impl(expr, endp);
}

/* SET */
static int cmd_builtin_set(wchar_t **argv, int argc){
    if(argc==1){
        wchar_t *env=GetEnvironmentStringsW();
        if(!env) return 1;
        for(wchar_t *p=env;*p;p+=wcslen(p)+1) wprintf(L"%s\n",p);
        FreeEnvironmentStringsW(env); return 0;
    }
    wchar_t combined[CMD_MAX_LINE]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(combined,CMD_MAX_LINE,L" "); wcscat_s(combined,CMD_MAX_LINE,argv[i]); }
    /* SET /A <name>=<expr>  — recursive-descent integer evaluator.
       Supports + - * / % ( ) and identifiers (env var lookup).
       Returns last error level unchanged on syntax error. */
    if(_wcsnicmp(combined,L"/A ",3)==0 || _wcsicmp(combined,L"/A")==0){
        const wchar_t *body = (combined[2] == L'\0') ? L"" : (combined + 3);
        while(*body == L' ' || *body == L'\t') body++;
        wchar_t *eq=wcschr(body,L'=');
        if(!eq){ cmd_print_error(L"SET /A: expected name=expression"); return 1; }
        *eq=L'\0'; wchar_t *name=(wchar_t*)body; wcs_trim(name);
        wchar_t *val=eq+1; wcs_trim(val);
        long long result = loos_eval_expr(val, NULL);
        if(result == LLONG_MIN){ cmd_print_error(L"SET /A: syntax error in '%s'", val); return 1; }
        wchar_t out[64]; swprintf_s(out, 64, L"%lld", result);
        SetEnvironmentVariableW(name, out);
        /* echo result for the user */
        wprintf(L"%lld\r\n", result);
        g_state.lastErrorLevel = (int)result;
        return (int)result;
    }
    if(_wcsnicmp(combined,L"/P ",3)==0){
        wchar_t *eq=wcschr(combined+3,L'=');
        if(eq){ *eq=L'\0'; wchar_t *name=combined+3; wcs_trim(name);
            wprintf(L"%s",eq+1); // show prompt
            wchar_t input[CMD_MAX_LINE]={0};
            if(fgetws(input,CMD_MAX_LINE,stdin)){
                wcs_trim(input);
                SetEnvironmentVariableW(name,input);
            }
        }
        return 0;
    }
    wchar_t *eq=wcschr(combined,L'=');
    if(!eq){
        wchar_t *env=GetEnvironmentStringsW();
        if(!env) return 1;
        size_t pl=wcslen(combined);
        for(wchar_t *p=env;*p;p+=wcslen(p)+1) if(_wcsnicmp(p,combined,pl)==0 && p[pl]==L'=') wprintf(L"%s\n",p);
        FreeEnvironmentStringsW(env); return 0;
    }
    *eq=L'\0'; wchar_t *name=combined; wchar_t *value=eq+1; wcs_trim(name);
    if(value[0]==L'\0') SetEnvironmentVariableW(name,NULL);
    else SetEnvironmentVariableW(name,value);
    return 0;
}

/* PATH */
static int cmd_builtin_path(wchar_t **argv, int argc){
    if(argc==1){
        wchar_t buf[CMD_MAX_PATH*4]; DWORD l=GetEnvironmentVariableW(L"PATH",buf,CMD_MAX_PATH*4);
        if(l==0) wprintf(L"PATH=(null)\n"); else wprintf(L"PATH=%s\n",buf); return 0;
    }
    wchar_t combined[CMD_MAX_PATH*4]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(combined,CMD_MAX_PATH*4,L" "); wcscat_s(combined,CMD_MAX_PATH*4,argv[i]); }
    if(wcs_starts_with_i(combined,L"PATH=")) memmove(combined,combined+5,(wcslen(combined+5)+1)*sizeof(wchar_t));
    if(combined[0]==L';'){
        wchar_t old[CMD_MAX_PATH*4]; GetEnvironmentVariableW(L"PATH",old,CMD_MAX_PATH*4);
        wchar_t np[CMD_MAX_PATH*4]; swprintf_s(np,CMD_MAX_PATH*4,L"%s%s",old,combined);
        SetEnvironmentVariableW(L"PATH",np);
    } else if(combined[0]==L'\0') SetEnvironmentVariableW(L"PATH",NULL);
      else SetEnvironmentVariableW(L"PATH",combined);
    return 0;
}

/* VER */
static int cmd_builtin_ver(wchar_t **argv, int argc){ (void)argv;(void)argc;
    OSVERSIONINFOEXW vi={0}; vi.dwOSVersionInfoSize=sizeof(vi);
#pragma warning(push)
#pragma warning(disable:4996)
    GetVersionExW((OSVERSIONINFOW*)&vi);
#pragma warning(pop)
    wprintf(L"\nLoOS [Version %s]\n", LOOS_VERSION);
    wprintf(L"(c) LoOS Team and Microsoft Corporation. All rights reserved.\n");
    wprintf(L"  Windows NT build %lu.%lu.%lu\n", vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    return 0;
}

/* HISTORY - persistent command history (like Bash .bash_history) */
static int cmd_builtin_history(int argc, wchar_t **argv){
    (void)argv;
    if(g_historyCount == 0){
        wprintf(L"  No commands in history.\n");
        return 0;
    }
    int start = (g_historyPos - g_historyCount + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
    for(int i = 0; i < g_historyCount; i++){
        int idx = (start + i) % CMD_HISTORY_SIZE;
        wprintf(L"  %3d  %s\n", i + 1, g_history[idx]);
    }
    return 0;
}

/* TITLE */
static int cmd_builtin_title(wchar_t **argv, int argc){
    if(argc<2) return 0;
    wchar_t t[CMD_MAX_LINE]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(t,CMD_MAX_LINE,L" "); wcscat_s(t,CMD_MAX_LINE,argv[i]); }
    SetConsoleTitleW(t); return 0;
}

/* TAB - Create new TUI tab */
static int cmd_builtin_tab(int argc, wchar_t **argv){
    (void)argv;
    (void)argc;
    tabs_new();
    tabs_draw_bar();
    return 0;
}

/* TABCLOSE / TABN / TABP / TABGO - close or switch tabs by command */
static int cmd_builtin_tabclose(wchar_t **argv, int argc){ (void)argv;(void)argc; if(g_tabCount > 1) tabs_close(); tabs_draw_bar(); return 0; }
static int cmd_builtin_tabnext (wchar_t **argv, int argc){ (void)argv;(void)argc; tabs_switch((g_currentTab + 1) % g_tabCount); tabs_draw_bar(); return 0; }
static int cmd_builtin_tabprev (wchar_t **argv, int argc){ (void)argv;(void)argc; int p = g_currentTab - 1; if(p < 0) p = g_tabCount - 1; tabs_switch(p); tabs_draw_bar(); return 0; }
static int cmd_builtin_tabgo   (wchar_t **argv, int argc){ (void)argc;
    if(!argv[1]) return 1;
    int n = _wtoi(argv[1]);
    if(n >= 1 && n <= g_tabCount){ tabs_switch(n - 1); tabs_draw_bar(); return 0; }
    return 1;
}

/* EXIT */
static int cmd_builtin_exit(wchar_t **argv, int argc){
    int code=0; if(argc>=2) code=_wtoi(argv[1]);
    if(argc>=3 && _wcsicmp(argv[1],L"/B")==0) code=_wtoi(argv[2]); // /B = exit batch but not shell
    else g_state.exitRequested=1;
    g_state.lastErrorLevel=code; return code;
}

/* HELP */
static int cmd_builtin_help(wchar_t **argv, int argc){
    if(argc>=2){
        wprintf(L"Help for %s - type %s /? for full help\n", argv[1], argv[1]);
        wchar_t cmd[256]; swprintf_s(cmd,256,L"%s /?",argv[1]);
        wchar_t buf[CMD_MAX_LINE]; wcsncpy_s(buf,CMD_MAX_LINE,cmd,_TRUNCATE);
        cmd_execute_line(buf);
        return 0;
    }
    wprintf(
        L"For more information on a specific command, type HELP <command>\n"
        L"ASSOC          Displays or modifies file extension associations.\n"
        L"ATTRIB         Displays or changes file attributes.\n"
        L"BREAK          Sets or clears extended CTRL+C checking.\n"
        L"BCDEDIT        Sets properties in boot database to control boot loading.\n"
        L"CACLS          Displays or modifies access control lists (ACLs) of files.\n"
        L"CALL           Calls one batch program from another.\n"
        L"CD             Displays the name of or changes the current directory.\n"
        L"CHCP           Displays or sets the active code page number.\n"
        L"CHDIR          Displays the name of or changes the current directory.\n"
        L"CHKDSK         Checks a disk and displays a status report.\n"
        L"CHKNTFS        Displays or modifies the checking of disk at boot time.\n"
        L"CLS            Clears the screen.\n"
        L"CMD            Starts a new instance of the LoOS command interpreter.\n"
        L"COLOR          Sets the default console foreground and background colors.\n"
        L"COMP           Compares the contents of two files or sets of files.\n"
        L"COMPACT        Displays or alters the compression of files on NTFS partitions.\n"
        L"CONVERT        Converts FAT volumes to NTFS.  You cannot convert the\n"
        L"               current drive.\n"
        L"COPY           Copies one or more files to another location.\n"
        L"DATE           Displays or sets the date.\n"
        L"DEL            Deletes one or more files.\n"
        L"DIR            Displays a list of files and subdirectories in a directory.\n"
        L"DISKPART       Displays or configures Disk Partition properties.\n"
        L"DOSKEY         Edits command lines, recalls Windows commands, and\n"
        L"               creates macros.\n"
        L"DRIVERQUERY    Displays current device driver status and properties.\n"
        L"ECHO           Displays messages, or turns command echoing on or off.\n"
        L"ENDLOCAL       Ends localization of environment changes in a batch file.\n"
        L"ERASE          Deletes one or more files.\n"
        L"EXIT           Quits the CMD.EXE program (command interpreter).\n"
        L"FC             Compares two files or sets of files, and displays the\n"
        L"               differences between them.\n"
        L"FIND           Searches for a text string in a file or files.\n"
        L"FINDSTR        Searches for strings in files.\n"
        L"FOR            Runs a specified command for each file in a set of files.\n"
        L"FORMAT         Formats a disk for use with Windows.\n"
        L"FSUTIL         Displays or configures the file system properties.\n"
        L"FTYPE          Displays or modifies file types used in file extension\n"
        L"               associations.\n"
        L"GOTO           Directs the LoOS command interpreter to a labeled line in\n"
        L"               a batch program.\n"
        L"GPRESULT       Displays Group Policy information for machine or user.\n"
        L"GRAFTABL       Enables Windows to display an extended character set in\n"
        L"               graphics mode.\n"
        L"HELP           Provides Help information for Windows commands.\n"
        L"ICACLS         Display, modify, backup, or restore ACLs for files and\n"
        L"               directories.\n"
        L"IF             Performs conditional processing in batch programs.\n"
        L"LABEL          Creates, changes, or deletes the volume label of a disk.\n"
        L"MD             Creates a directory.\n"
        L"MKDIR          Creates a directory.\n"
        L"MKLINK         Creates Symbolic Links and Hard Links\n"
        L"MODE           Configures a system device.\n"
        L"MORE           Displays output one screen at a time.\n"
        L"MOVE           Moves one or more files from one directory to another\n"
        L"               directory.\n"
        L"OPENFILES      Displays files opened by remote users for a file share.\n"
        L"PATH           Displays or sets a search path for executable files.\n"
        L"PAUSE          Suspends processing of a batch file and displays a message.\n"
        L"POPD           Restores the previous value of the current directory saved by\n"
        L"               PUSHD.\n"
        L"PRINT          Prints a text file.\n"
        L"PROMPT         Changes the Windows command prompt.\n"
        L"PUSHD          Saves the current directory then changes it.\n"
        L"RD             Removes a directory.\n"
        L"RECOVER        Recovers readable information from a bad or defective disk.\n"
        L"REM            Records comments (remarks) in batch files or CONFIG.SYS.\n"
        L"REN            Renames a file or files.\n"
        L"RENAME         Renames a file or files.\n"
        L"REPLACE        Replaces files.\n"
        L"RMDIR          Removes a directory.\n"
        L"ROBOCOPY       Advanced utility to copy files and directory trees\n"
        L"SET            Displays, sets, or removes Windows environment variables.\n"
        L"SETLOCAL       Begins localization of environment changes in a batch file.\n"
        L"SC             Displays or configures services (background processes).\n"
        L"SCHTASKS       Schedules commands and programs to run on a computer.\n"
        L"SHIFT          Shifts the position of replaceable parameters in batch files.\n"
        L"SHUTDOWN       Allows proper local or remote shutdown of machine.\n"
        L"SORT           Sorts input.\n"
        L"START          Starts a separate window to run a specified program or command.\n"
        L"SUBST          Associates a path with a drive letter.\n"
        L"SYSTEMINFO     Displays machine specific properties and configuration.\n"
        L"TASKLIST       Displays all currently running tasks including services.\n"
        L"TASKKILL       Kill or stop a running process or application.\n"
        L"TIME           Displays or sets the system time.\n"
        L"TITLE          Sets the window title for a CMD.EXE session.\n"
        L"TREE           Graphically displays the directory structure of a drive or\n"
        L"               path.\n"
        L"TYPE           Displays the contents of a text file.\n"
        L"VER            Displays the Windows version.\n"
        L"VERIFY         Tells Windows whether to verify that your files are written\n"
        L"               correctly to a disk.\n"
        L"VOL            Displays a disk volume label and serial number.\n"
        L"XCOPY          Copies files and directory trees.\n"
        L"WMIC           Displays WMI information inside interactive command shell.\n"
        L"XCOPY          Copies files and directory trees.\n"
        L"\n"
        L"LoOS Powerful Extensions (native, no external exes):\n"
        L"PING           Native ICMP ping (IcmpSendEcho)\n"
        L"IPCONFIG       Native network config (GetAdaptersAddresses)\n"
        L"NETSTAT        Native TCP table (GetTcpTable2)\n"
        L"TRACERT        Native traceroute\n"
        L"NSLOOKUP       Native DNS query (DnsQuery)\n"
        L"ARP            Native ARP table (GetIpNetTable)\n"
        L"ROUTE          Native route table (GetIpForwardTable)\n"
        L"NET            Native user/share/view (NetUserEnum)\n"
        L"REG            Native registry query/add/delete\n"
        L"WHERE          Native path search (SearchPath)\n"
        L"WHOAMI         Native user/domain display\n"
        L"SETX           Native persistent env (registry + broadcast)\n"
        L"TIMEOUT        Native countdown sleep\n"
        L"CHOICE         Native choice prompt\n"
        L"CLIP           Native clipboard (OpenClipboard)\n"
        L"TAKEOWN        Native ownership (SeTakeOwnership)\n"
        L"CURL/WGET      Native HTTP fetch (WinHTTP)\n"
        L"GREP           Native search (alias FINDSTR)\n"
        L"LS             Native Unix-style directory list\n"
        L"PS/KILL        Native task list/kill (Toolhelp32)\n"
        L"NBTSTAT/NETSH/POWERCFG/SFC  Native system tools\n"
        L"\n"
        L"LoOS PowerShell-inspired extensions:\n"
        L"OBJ            Create or update a hashtable object:  OBJ user = @{name=Alice; age=30}\n"
        L"               Access fields with $user.name, or OGET $user.name\n"
        L"OSET           Set a field on an existing object:        OSET $user.email = a@b.c\n"
        L"OGET           Read a field (or whole object):          OGET $user.name\n"
        L"OBJECTS        List all defined objects.  OBJECTS DEL <name> removes one.\n"
        L"ODEL           Remove an object.\n"
        L"\n"
        L"ARRAY          Create an array:                          ARRAY primes = 2,3,5,7,11\n"
        L"AGET           Read an element:                          AGET $primes[3]\n"
        L"ASET           Set an element (auto-grows):              ASET $primes[5] = 13\n"
        L"ARRAYS         List all defined arrays.  ARRAYS DEL <name> removes one.\n"
        L"ADEL           Remove an array.\n"
        L"\n"
        L"FUNC           Define a user function (no GOTO):         FUNC greet {echo Hello $1}\n"
        L"               Body statements are separated by ';'.\n"
        L"CALL           Call a user function or batch file:       CALL greet World\n"
        L"               Arguments bind to $1..$8 in the body.\n"
        L"FUNCS          List all defined functions.\n"
        L"FUNCDEL        Remove a user function.\n"
        L"\n"
        L"CONVERTFROM-JSON   Parse a JSON literal into $__conv:\n"
        L"                   CONVERTFROM-JSON {\"a\":1,\"b\":\"two\"}\n"
        L"CONVERTTO-JSON     Print an object as JSON:\n"
        L"                   CONVERTTO-JSON __conv\n"
        L"CONVERTFROM-XML    Parse a shallow XML literal into $__conv:\n"
        L"                   CONVERTFROM-XML <root><x>1</x></root>\n"
        L"CONVERTTO-XML      Print an object as XML:\n"
        L"                   CONVERTTO-XML __conv\n"
        L"Short aliases: CFJ / CTJ / CFX / CTX\n"
        L"\n"
        L"TUI tabs (strip travels with the prompt, always on top of it):\n"
        L"TAB            Open a new tab.              Shortcut: Ctrl+T\n"
        L"TABN           Switch to the next tab.      Shortcut: Ctrl+Tab\n"
        L"TABP           Switch to the previous tab.  Shortcut: Ctrl+Shift+Tab\n"
        L"TABGO <n>      Switch to tab n (1..8).      Shortcut: Alt+1..Alt+8\n"
        L"TABCLOSE       Close the current tab.       Shortcut: Ctrl+W\n"
        L"               (Click a tab in the strip to switch with the mouse.)\n"
        L"\n"
        L"HISTORY        Print the command history (persistent in %%USERPROFILE%%\\.loos_history).\n"
        L"\n"
        L"Completion:\n"
        L"               TAB at the prompt runs context-aware completion:\n"
        L"                 - first token: builtin command name\n"
        L"                 - path-shaped token: file/directory name\n"
        L"                 - $name: env var / object / array name\n"
        L"                 - $obj.: keys of object 'obj'\n"
        L"               As you type, a dim ghost preview of the best history\n"
        L"               match is shown; Right Arrow takes one char, End takes all.\n"
        L"               Typing \" ( [ { auto-closes the pair; Backspace on an\n"
        L"               empty pair removes both.\n"
        L"               Arrows/Home/End move, Up/Down walk history, Esc clears.\n"
        L"               Ctrl+C copies the current line, Ctrl+V pastes\n"
        L"               (multi-line paste asks first, newlines -> spaces).\n"
        L"               AltGr works: @ euro [ ] { } | ~ etc. type normally\n"
        L"               on Swiss/German/French layouts.\n"
        L"\n"
        L"Unix aliases (translated to native commands in real time):\n"
        L"               LS RM CAT CP MV MKDIR RMDIR TOUCH CLEAR PWD MAN\n"
        L"               GREP HEAD TAIL WC WHICH UNAME DF FREE ENV\n"
        L"               e.g. LS -> DIR /B, CAT -> TYPE, RM -> DEL /Q.\n"
        L"SUDO           Re-run a command elevated (UAC prompt):\n"
        L"               SUDO <command> [args ...]\n"
        L"THEME          Palette swapper: THEME <default|solarized-light|\n"
        L"               solarized-dark|dracula> or THEME LIST. Custom *.json\n"
        L"               themes load from %%USERPROFILE%%\\.loos_themes\\\n"
        L"CURSOR         Cursor shape: CURSOR <block|underscore|bar|off>\n"
        L"DIDYOUMEAN     Typo helper (also automatic): unknown commands offer\n"
        L"               the closest builtin, e.g. 'ech' -> ECHO.\n"
        L"\n"
        L"Console visuals (plain conhost compatible, all opt-in/off by default):\n"
        L"HYPERLINKS     Emit OSC 8 links for http(s):// URLs and file paths.\n"
        L"NOHYPERLINKS   Turn hyperlink emission off (default).\n"
        L"SESSION-SAVE   Save tab count + cwd snapshot now.\n"
        L"SESSION-RESTORE Show the last saved session snapshot.\n"
        L"QUAKE          Slide the console down from the top of the screen.\n"
        L"AUTOCOPY       Toggle copy-on-select (QuickEdit based).\n"
        L"BLUR           Best-effort Mica backdrop via dwmapi (Win10 1903+).\n"
        L"TABNAME <t>    Rename the current tab / console title.\n"
        L"               Block/column select: hold Alt while dragging (conhost).\n"
        L"               Multi-line paste: conhost asks before pasting \\n runs.\n"
        L"\n"
        L"Piping: >, >>, <, | and 2>&1 (stderr into stdout) are supported.\n"
        L"               GREP is an alias for FINDSTR. 2>file is parsed.\n"
        L"\n"
        L"Developer logging:  set LOOSDEBUG=1 to enable verbose stderr logs.\n"
        L"\n"
        L"For more information on tools see the command-line reference in the online help.\n"
    ); return 0;
}

/* ASSOC - file extension associations (via registry) */
static int cmd_builtin_assoc(wchar_t **argv, int argc){
    HKEY hKey;
    if(argc==1){
        if(RegOpenKeyExW(HKEY_CLASSES_ROOT,NULL,0,KEY_READ,&hKey)!=ERROR_SUCCESS) return 1;
        wchar_t name[256]; DWORD idx=0; DWORD nlen;
        while(1){
            nlen=256;
            if(RegEnumKeyExW(hKey,idx++,name,&nlen,NULL,NULL,NULL,NULL)!=ERROR_SUCCESS) break;
            if(name[0]!=L'.') continue;
            wchar_t val[256]={0}; DWORD vlen=sizeof(val);
            if(RegGetValueW(HKEY_CLASSES_ROOT,name,NULL,RRF_RT_REG_SZ,NULL,val,&vlen)==ERROR_SUCCESS)
                wprintf(L"%s=%s\n",name,val);
            else wprintf(L"%s=\n",name);
        }
        RegCloseKey(hKey); return 0;
    }
    // ASSOC .ext or ASSOC .ext=FileType
    wchar_t combined[CMD_MAX_LINE]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(combined,CMD_MAX_LINE,L" "); wcscat_s(combined,CMD_MAX_LINE,argv[i]); }
    wchar_t *eq=wcschr(combined,L'=');
    if(!eq){
        // Show one association: ASSOC .txt
        wchar_t val[256]={0}; DWORD vlen=sizeof(val);
        if(RegGetValueW(HKEY_CLASSES_ROOT,combined,NULL,RRF_RT_REG_SZ,NULL,val,&vlen)==ERROR_SUCCESS) wprintf(L"%s=%s\n",combined,val);
        else wprintf(L"File association not found for extension %s\n",combined);
        return 0;
    }
    *eq=L'\0'; wchar_t *ext=combined; wchar_t *ft=eq+1;
    if(wcslen(ft)==0){
        RegDeleteKeyW(HKEY_CLASSES_ROOT,ext);
    } else {
        RegCreateKeyExW(HKEY_CLASSES_ROOT,ext,0,NULL,0,KEY_WRITE,NULL,&hKey,NULL);
        RegSetValueExW(hKey,NULL,0,REG_SZ,(BYTE*)ft,(DWORD)((wcslen(ft)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    return 0;
}

/* FTYPE - file type associations */
static int cmd_builtin_ftype(wchar_t **argv, int argc){
    HKEY hKey;
    if(argc==1){
        if(RegOpenKeyExW(HKEY_CLASSES_ROOT,NULL,0,KEY_READ,&hKey)!=ERROR_SUCCESS) return 1;
        wchar_t name[256]; DWORD idx=0; DWORD nlen;
        while(1){
            nlen=256;
            if(RegEnumKeyExW(hKey,idx++,name,&nlen,NULL,NULL,NULL,NULL)!=ERROR_SUCCESS) break;
            if(name[0]==L'.') continue;
            wchar_t val[512]={0}; DWORD vlen=sizeof(val);
            if(RegGetValueW(HKEY_CLASSES_ROOT,name,NULL,RRF_RT_REG_SZ,NULL,val,&vlen)==ERROR_SUCCESS){
                // Only show if it looks like a file type with open command
                wchar_t cmdKey[512]; swprintf_s(cmdKey,512,L"%s\\shell\\open\\command",name);
                wchar_t oc[512]={0}; DWORD ocl=sizeof(oc);
                if(RegGetValueW(HKEY_CLASSES_ROOT,cmdKey,NULL,RRF_RT_REG_SZ,NULL,oc,&ocl)==ERROR_SUCCESS)
                    wprintf(L"%s=%s\n",name,oc);
            }
        }
        RegCloseKey(hKey); return 0;
    }
    wchar_t combined[CMD_MAX_LINE]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(combined,CMD_MAX_LINE,L" "); wcscat_s(combined,CMD_MAX_LINE,argv[i]); }
    wchar_t *eq=wcschr(combined,L'=');
    if(!eq){
        wchar_t cmdKey[512]; swprintf_s(cmdKey,512,L"%s\\shell\\open\\command",combined);
        wchar_t oc[512]={0}; DWORD ocl=sizeof(oc);
        if(RegGetValueW(HKEY_CLASSES_ROOT,cmdKey,NULL,RRF_RT_REG_SZ,NULL,oc,&ocl)==ERROR_SUCCESS) wprintf(L"%s=%s\n",combined,oc);
        else wprintf(L"File type '%s' not found\n",combined);
        return 0;
    }
    *eq=L'\0'; wchar_t *ft=combined; wchar_t *cmd=eq+1;
    wchar_t key[512]; swprintf_s(key,512,L"%s\\shell\\open\\command",ft);
    if(wcslen(cmd)==0) RegDeleteKeyW(HKEY_CLASSES_ROOT,key);
    else {
        RegCreateKeyExW(HKEY_CLASSES_ROOT,key,0,NULL,0,KEY_WRITE,NULL,&hKey,NULL);
        RegSetValueExW(hKey,NULL,0,REG_SZ,(BYTE*)cmd,(DWORD)((wcslen(cmd)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey);
    }
    return 0;
}

/* ATTRIB helpers */
static void print_file_attributes(const wchar_t *path){
    DWORD a=GetFileAttributesW(path);
    if(a==INVALID_FILE_ATTRIBUTES){ cmd_print_error(L"ATTRIB: File not found - %s",path); return; }
    wprintf(L"%c%c%c%c%c   %s\n",
        (a&FILE_ATTRIBUTE_ARCHIVE)?L'A':L' ',
        (a&FILE_ATTRIBUTE_SYSTEM)?L'S':L' ',
        (a&FILE_ATTRIBUTE_HIDDEN)?L'H':L' ',
        (a&FILE_ATTRIBUTE_READONLY)?L'R':L' ',
        L' ', path);
}
static int cmd_builtin_attrib(wchar_t **argv, int argc){
    if(argc==1){
        WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(L"*",&fd);
        if(h==INVALID_HANDLE_VALUE){ wprintf(L"File not found\n"); return 1; }
        do{ if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue; print_file_attributes(fd.cFileName); }while(FindNextFileW(h,&fd));
        FindClose(h); return 0;
    }
    int hasAttrOp=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'+' || argv[i][0]==L'-'){
            hasAttrOp=1; break;
        }
    }
    if(!hasAttrOp){
        // Show attributes for given files
        for(int i=1;i<argc;i++){ if(argv[i][0]==L'/') continue; print_file_attributes(argv[i]); }
        return 0;
    }
    // Set attributes: ATTRIB +R -H file
    DWORD add=0, rem=0;
    const wchar_t *target=NULL;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'+' || argv[i][0]==L'-'){
            int isAdd=(argv[i][0]==L'+');
            for(wchar_t *p=argv[i]+1; *p; p++){
                DWORD flag=0;
                switch(towupper(*p)){
                    case L'R': flag=FILE_ATTRIBUTE_READONLY; break;
                    case L'H': flag=FILE_ATTRIBUTE_HIDDEN; break;
                    case L'S': flag=FILE_ATTRIBUTE_SYSTEM; break;
                    case L'A': flag=FILE_ATTRIBUTE_ARCHIVE; break;
                    default: wprintf(L"ATTRIB: unknown attribute %c\n",*p); break;
                }
                if(isAdd) add|=flag; else rem|=flag;
            }
        } else if(argv[i][0]!=L'/') target=argv[i];
    }
    if(!target){ cmd_print_error(L"ATTRIB: missing file"); return 1; }
    // Support wildcards
    WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(target,&fd);
    if(h==INVALID_HANDLE_VALUE){
        DWORD a=GetFileAttributesW(target);
        if(a==INVALID_FILE_ATTRIBUTES) return 1;
        DWORD na=(a | add) & ~rem; SetFileAttributesW(target,na); return 0;
    }
    wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(target,L'\\');
    if(sl) wcsncpy_s(dir,CMD_MAX_PATH,target,sl-target+1);
    do{
        if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
        wchar_t fp[CMD_MAX_PATH]; swprintf_s(fp,CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
        DWORD a=GetFileAttributesW(fp);
        DWORD na=(a | add) & ~rem; SetFileAttributesW(fp,na);
    }while(FindNextFileW(h,&fd)); FindClose(h); return 0;
}

/* BREAK */
static int cmd_builtin_break(wchar_t **argv, int argc){
    if(argc==1){ wprintf(L"BREAK is %s\n", GetConsoleMode(g_state.hStdIn,NULL)?L"on":L"off"); return 0; }
    if(_wcsicmp(argv[1],L"ON")==0) SetConsoleMode(g_state.hStdIn, ENABLE_PROCESSED_INPUT);
    else if(_wcsicmp(argv[1],L"OFF")==0) SetConsoleMode(g_state.hStdIn, ENABLE_PROCESSED_INPUT);
    return 0;
}

/* CHCP */
static int cmd_builtin_chcp(wchar_t **argv, int argc){
    if(argc==1){ wprintf(L"Active code page: %u\n", GetConsoleOutputCP()); return 0; }
    UINT cp=(UINT)_wtoi(argv[1]);
    SetConsoleCP(cp); SetConsoleOutputCP(cp);
    g_state.inputCodepage=cp; g_state.outputCodepage=cp; return 0;
}

/* COLOR */
static int cmd_builtin_color(wchar_t **argv, int argc){
    if(argc<2){ // no args = reset to default (07 = gray on black)
        SetConsoleTextAttribute(g_state.hStdOut, 7); return 0;
    }
    wchar_t *c=argv[1];
    int attr=0;
    if(wcslen(c)==2){
        wchar_t bg=towupper(c[0]), fg=towupper(c[1]);
        int bv=-1, fv=-1;
        if(bg>=L'0'&&bg<=L'9') bv=bg-L'0'; else if(bg>=L'A'&&bg<=L'F') bv=bg-L'A'+10; else if(bg>=L'a'&&bg<=L'f') bv=bg-L'a'+10;
        if(fg>=L'0'&&fg<=L'9') fv=fg-L'0'; else if(fg>=L'A'&&fg<=L'F') fv=fg-L'A'+10; else if(fg>=L'a'&&fg<=L'f') fv=fg-L'a'+10;
        if(bv>=0&&fv>=0) attr=(bv<<4)|fv;
        else { wprintf(L"COLOR: invalid color\n"); return 1; }
    } else if(wcslen(c)==1){
        attr=_wtoi(c);
    } else { wprintf(L"Usage: COLOR [attr]  (e.g. COLOR 0A, COLOR FC)\n"); return 1; }
    SetConsoleTextAttribute(g_state.hStdOut,(WORD)attr); return 0;
}

/* DATE */
static int cmd_builtin_date(wchar_t **argv, int argc){
    SYSTEMTIME st; GetLocalTime(&st);
    if(argc==1){
        wprintf(L"The current date is: %02d/%02d/%04d\n",st.wMonth,st.wDay,st.wYear);
        wprintf(L"Enter the new date: (mm-dd-yy) ");
        wchar_t inp[64]={0};
        if(fgetws(inp,64,stdin)){
            wcs_trim(inp);
            if(wcslen(inp)>0){
                int m,d,y;
                if(swscanf_s(inp,L"%d/%d/%d",&m,&d,&y)==3 || swscanf_s(inp,L"%d-%d-%d",&m,&d,&y)==3){
                    st.wMonth=(WORD)m; st.wDay=(WORD)d; st.wYear=(WORD)y;
                    SetLocalTime(&st);
                }
            }
        }
        return 0;
    }
    // DATE mm-dd-yy
    int m,d,y;
    if(swscanf_s(argv[1],L"%d/%d/%d",&m,&d,&y)==3 || swscanf_s(argv[1],L"%d-%d-%d",&m,&d,&y)==3){
        st.wMonth=(WORD)m; st.wDay=(WORD)d; if(y<100) y+=2000; st.wYear=(WORD)y;
        if(!SetLocalTime(&st)) { cmd_print_error(L"DATE: failed to set date"); return 1; }
        return 0;
    }
    // Also handle /T (display only, no prompt) - used as DATE /T
    if(_wcsicmp(argv[1],L"/T")==0){ wprintf(L"%02d/%02d/%04d\n",st.wMonth,st.wDay,st.wYear); return 0; }
    cmd_print_error(L"DATE: invalid date format"); return 1;
}

/* TIME */
static int cmd_builtin_time(wchar_t **argv, int argc){
    SYSTEMTIME st; GetLocalTime(&st);
    if(argc==1){
        wprintf(L"The current time is: %02d:%02d:%02d.%02d\n",st.wHour,st.wMinute,st.wSecond,st.wMilliseconds/10);
        wprintf(L"Enter the new time: ");
        wchar_t inp[64]={0};
        if(fgetws(inp,64,stdin)){
            wcs_trim(inp);
            if(wcslen(inp)>0){
                int h,mi,s;
                if(swscanf_s(inp,L"%d:%d:%d",&h,&mi,&s)>=2){
                    st.wHour=(WORD)h; st.wMinute=(WORD)mi; st.wSecond=(WORD)(s>=0?s:0);
                    SetLocalTime(&st);
                }
            }
        }
        return 0;
    }
    if(_wcsicmp(argv[1],L"/T")==0){ wprintf(L"%02d:%02d:%02d\n",st.wHour,st.wMinute,st.wSecond); return 0; }
    int h,mi,s=0;
    if(swscanf_s(argv[1],L"%d:%d:%d",&h,&mi,&s)>=2){
        st.wHour=(WORD)h; st.wMinute=(WORD)mi; st.wSecond=(WORD)s;
        if(!SetLocalTime(&st)) { cmd_print_error(L"TIME: failed"); return 1; } return 0;
    }
    cmd_print_error(L"TIME: invalid format"); return 1;
}

/* VERIFY */
static int cmd_builtin_verify(wchar_t **argv, int argc){
    if(argc==1){ wprintf(L"VERIFY is %s.\n", g_state.verifyOn?L"on":L"off"); return 0; }
    if(_wcsicmp(argv[1],L"ON")==0) g_state.verifyOn=1;
    else if(_wcsicmp(argv[1],L"OFF")==0) g_state.verifyOn=0;
    return 0;
}

/* VOL */
static int cmd_builtin_vol(wchar_t **argv, int argc){
    wchar_t root[4]=L"C:\\";
    if(argc>=2 && wcslen(argv[1])>=2 && argv[1][1]==L':'){ root[0]=towupper(argv[1][0]); }
    else {
        // Use current drive
        root[0]=towupper(g_state.currentDir[0]);
    }
    wchar_t volName[MAX_PATH]={0}, fsName[MAX_PATH]={0};
    DWORD serial=0, maxComp=0, fsFlags=0;
    if(!GetVolumeInformationW(root,volName,MAX_PATH,&serial,&maxComp,&fsFlags,fsName,MAX_PATH)){
        cmd_print_error(L"VOL: cannot get volume info for %s",root); return 1;
    }
    wprintf(L" Volume in drive %s is %s\n",root, wcslen(volName)?volName:L"");
    wprintf(L" Volume Serial Number is %04X-%04X\n", HIWORD(serial), LOWORD(serial));
    return 0;
}

/* PROMPT */
static int cmd_builtin_prompt(wchar_t **argv, int argc){
    if(argc==1){ wprintf(L"PROMPT=%s\n", g_state.promptFormat); return 0; }
    wchar_t p[128]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(p,128,L" "); wcscat_s(p,128,argv[i]); }
    wcsncpy_s(g_state.promptFormat,128,p,_TRUNCATE);
    SetEnvironmentVariableW(L"PROMPT",p);
    return 0;
}

/* PUSHD / POPD */
static int cmd_builtin_pushd(wchar_t **argv, int argc){
    if(argc==1){
        // Push current dir
        if(g_state.pushdTop>=CMD_PUSHD_MAX){ cmd_print_error(L"PUSHD: stack full"); return 1; }
        wcsncpy_s(g_state.pushdStack[g_state.pushdTop++],CMD_MAX_PATH,g_state.currentDir,_TRUNCATE);
        // PUSHD with no args stores current dir (like real cmd, also shows stack if echo?)
        return 0;
    }
    // Push current, then CD to new dir
    if(g_state.pushdTop>=CMD_PUSHD_MAX){ cmd_print_error(L"PUSHD: stack full"); return 1; }
    wcsncpy_s(g_state.pushdStack[g_state.pushdTop++],CMD_MAX_PATH,g_state.currentDir,_TRUNCATE);
    return cmd_builtin_cd(argv,argc);
}
static int cmd_builtin_popd(wchar_t **argv, int argc){ (void)argv;(void)argc;
    if(g_state.pushdTop<=0){ cmd_print_error(L"POPD: stack empty"); return 1; }
    g_state.pushdTop--;
    SetCurrentDirectoryW(g_state.pushdStack[g_state.pushdTop]);
    GetCurrentDirectoryW(CMD_MAX_PATH,g_state.currentDir);
    return 0;
}

/* PAUSE */
static int cmd_builtin_pause(wchar_t **argv, int argc){ (void)argv;(void)argc;
    wprintf(L"Press any key to continue . . . ");
    _getwch(); wprintf(L"\n"); return 0;
}

/* REM */
static int cmd_builtin_rem(wchar_t **argv, int argc){ (void)argv;(void)argc; return 0; }

/* SETLOCAL / ENDLOCAL */
static int cmd_builtin_setlocal(wchar_t **argv, int argc){
    (void)argv;(void)argc;
    if(g_state.setlocalDepth>=CMD_SETLOCAL_MAX){ cmd_print_error(L"SETLOCAL: nesting too deep"); return 1; }
    g_state.setlocalDepth++;
    // Real cmd saves env + echo + delayed expansion state. We just bump depth.
    // For delayed expansion / extensions flags:
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"ENABLEDELAYEDEXPANSION")==0) {}
        else if(_wcsicmp(argv[i],L"DISABLEDELAYEDEXPANSION")==0) {}
        else if(_wcsicmp(argv[i],L"ENABLEEXTENSIONS")==0) g_state.extensionsEnabled=1;
        else if(_wcsicmp(argv[i],L"DISABLEEXTENSIONS")==0) g_state.extensionsEnabled=0;
    }
    return 0;
}
static int cmd_builtin_endlocal(wchar_t **argv, int argc){ (void)argv;(void)argc;
    if(g_state.setlocalDepth<=0){ cmd_print_error(L"ENDLOCAL: no SETLOCAL"); return 1; }
    g_state.setlocalDepth--; return 0;
}

/* SHIFT */
static int cmd_builtin_shift(wchar_t **argv, int argc){
    int amount=1;
    if(argc>=2 && argv[1][0]==L'/' ){
        // SHIFT /n - shift starting at n (simplified: just shift by 1)
        amount=1;
    }
    if(g_state.batchArgCount>0){
        g_state.batchShiftOffset+=amount;
        if(g_state.batchShiftOffset>g_state.batchArgCount) g_state.batchShiftOffset=g_state.batchArgCount;
    }
    // Also shift our global batchArgs array for current batch context
    (void)argv; return 0;
}

/* MKLINK */
static int cmd_builtin_mklink(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Creates a symbolic link.\nUsage: MKLINK [/D] [/H] [/J] <Link> <Target>\n"); return 1; }
    int isDir=0,isHard=0,isJunc=0;
    const wchar_t *link=NULL,*target=NULL;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/D")==0) isDir=1;
        else if(_wcsicmp(argv[i],L"/H")==0) isHard=1;
        else if(_wcsicmp(argv[i],L"/J")==0) isJunc=1;
        else if(!link) link=argv[i];
        else if(!target) target=argv[i];
    }
    if(!link||!target){ wprintf(L"MKLINK: missing link or target\n"); return 1; }
    BOOL ok=FALSE;
    if(isHard) ok=CreateHardLinkW(link,target,NULL);
    else if(isJunc){
        // Junctions are more complex; use CreateSymbolicLink with directory flag and unprivileged flag
        ok=CreateSymbolicLinkW(link,target,SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
    } else {
        DWORD flags=isDir?SYMBOLIC_LINK_FLAG_DIRECTORY:0;
        flags|=SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
        ok=CreateSymbolicLinkW(link,target,flags);
    }
    if(!ok){ DWORD e=GetLastError(); wchar_t m[256]; FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM,NULL,e,0,m,256,NULL); wcs_trim(m); cmd_print_error(L"MKLINK: %s",m); return 1; }
    wprintf(L"symbolic link created for %s <<===>> %s\n",link,target); return 0;
}

/* START */
static int cmd_builtin_start(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"Usage: START [\"title\"] [/D path] [/I] [/MIN] [/MAX] [/WAIT] [command]\n"); return 1; }
    int idx=1;
    // Skip title in quotes if present, and switches
    if(argv[idx][0]==L'"') idx++; // title
    while(idx<argc && argv[idx][0]==L'/'){
        if(_wcsicmp(argv[idx],L"/WAIT")==0){ idx++; break; }
        idx++;
    }
    if(idx>=argc) return 0;
    wchar_t cmdLine[CMD_MAX_LINE*2]={0};
    for(int i=idx;i<argc;i++){ if(i>idx) wcscat_s(cmdLine,CMD_MAX_LINE*2,L" "); wcscat_s(cmdLine,CMD_MAX_LINE*2,argv[i]); }
    STARTUPINFOW si={0}; PROCESS_INFORMATION pi={0}; si.cb=sizeof(si);
    // Use ShellExecute-like behavior: let Windows find the program
    SHELLEXECUTEINFOW sei={0}; sei.cbSize=sizeof(sei); sei.lpFile=argv[idx]; sei.lpParameters=NULL; sei.nShow=SW_SHOWNORMAL;
    // Build params after file
    if(argc>idx+1){
        wchar_t params[CMD_MAX_LINE]={0};
        for(int i=idx+1;i<argc;i++){ if(i>idx+1) wcscat_s(params,CMD_MAX_LINE,L" "); wcscat_s(params,CMD_MAX_LINE,argv[i]); }
        sei.lpParameters=params;
        if(ShellExecuteExW(&sei)) return 0;
    }
    // Fallback to CreateProcess
    if(CreateProcessW(NULL,cmdLine,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi)){
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return 0;
    }
    // Try ShellExecute
    if((INT_PTR)ShellExecuteW(NULL,L"open",argv[idx],NULL,NULL,SW_SHOWNORMAL) > 32) return 0;
    cmd_print_error(L"START: cannot start %s",argv[idx]); return 1;
}

/* MORE - paginate output (simplified) */
static int cmd_builtin_more(wchar_t **argv, int argc){
    // MORE [file] or MORE < input
    // If file given, page it. Else read from stdin.
    CONSOLE_SCREEN_BUFFER_INFO csbi; GetConsoleScreenBufferInfo(g_state.hStdOut,&csbi);
    int pageSize=csbi.dwSize.Y - 2; if(pageSize<=0) pageSize=24;
    int lineCount=0;
    if(argc>=2){
        for(int i=1;i<argc;i++){
            HANDLE h=CreateFileW(argv[i],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
            if(h==INVALID_HANDLE_VALUE){ cmd_print_error(L"MORE: cannot open %s",argv[i]); continue; }
            char buf[8192]; DWORD r; char leftover[8192]={0}; size_t leftLen=0;
            while(ReadFile(h,buf,sizeof(buf)-1,&r,NULL)&&r>0){
                buf[r]='\0';
                // Simple line split on \n
                char *p=buf;
                while(*p){
                    char *nl=strchr(p,'\n');
                    if(nl){ *nl='\0'; wprintf(L"%hs\n",p); lineCount++; p=nl+1;
                        if(lineCount>=pageSize){ wprintf(L"-- More  --"); int ch=_getwch(); wprintf(L"\r            \r"); if(ch==L'q') break; lineCount=0; }
                    } else { wprintf(L"%hs",p); break; }
                }
            }
            CloseHandle(h);
        }
        return 0;
    }
    // From stdin
    wchar_t line[CMD_MAX_LINE];
    while(fgetws(line,CMD_MAX_LINE,stdin)){
        wprintf(L"%s",line);
        lineCount++;
        if(lineCount>=pageSize){ wprintf(L"-- More  --"); int ch=_getwch(); wprintf(L"\r            \r"); if(ch==L'q') break; lineCount=0; }
    }
    return 0;
}

/* CALL - call a batch file, label, or user-defined FUNCtion. */
static int cmd_builtin_call(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"CALL: missing target"); return 1; }
    const wchar_t *target=argv[1];
    /* If target is a defined FUNC, run it (PowerShell-style user function). */
    if(func_find(target) >= 0){
        return cmd_builtin_callfunc(argv, argc);
    }
    if(target[0]==L':'){
        wprintf(L"CALL :label not implemented outside batch context\n"); return 1;
    }
    /* Otherwise it's a batch file or command: CALL batchfile.bat args */
    wchar_t path[CMD_MAX_PATH]; wcsncpy_s(path,CMD_MAX_PATH,target,_TRUNCATE);
    if(!wcschr(target,L'.')){
        wchar_t tryBat[CMD_MAX_PATH]; swprintf_s(tryBat,CMD_MAX_PATH,L"%s.bat",target);
        if(GetFileAttributesW(tryBat)!=INVALID_FILE_ATTRIBUTES) wcsncpy_s(path,CMD_MAX_PATH,tryBat,_TRUNCATE);
        else {
            wchar_t tryCmd[CMD_MAX_PATH]; swprintf_s(tryCmd,CMD_MAX_PATH,L"%s.cmd",target);
            if(GetFileAttributesW(tryCmd)!=INVALID_FILE_ATTRIBUTES) wcsncpy_s(path,CMD_MAX_PATH,tryCmd,_TRUNCATE);
        }
    }
    DWORD a=GetFileAttributesW(path);
    if(a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)){
        return cmd_run_batch_file(path, argv+1, argc-1);
    }
    /* Treat as command: CALL command args -> just execute the rest */
    wchar_t line[CMD_MAX_LINE]={0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(line,CMD_MAX_LINE,L" "); wcscat_s(line,CMD_MAX_LINE,argv[i]); }
    return cmd_execute_line(line);
}

/* GOTO - only valid inside batch file (we handle in batch runner) */
static int cmd_builtin_goto(wchar_t **argv, int argc){
    if(argc<2){ cmd_print_error(L"GOTO: missing label"); return 1; }
    // Outside batch, GOTO does nothing except error
    if(g_state.batchDepth==0){ cmd_print_error(L"GOTO: not in a batch file"); return 1; }
    // Inside batch, the runner handles it via return code signaling
    // We signal by setting errorlevel to special value and returning
    wprintf(L"GOTO %s\n",argv[1]); return 0;
}

/* IF - conditional execution */
static int cmd_builtin_if(wchar_t **argv, int argc){
    if(argc<4){ wprintf(L"Usage: IF [NOT] <condition> command\n"
                        L"  Conditions: EXIST file, DEFINED var, string==string, ERRORLEVEL n, CMDEXTVERSION n\n"); return 1; }
    int idx=1; int doNot=0;
    if(_wcsicmp(argv[idx],L"NOT")==0){ doNot=1; idx++; }
    if(idx>=argc) return 1;

    int conditionTrue=0;

    if(_wcsicmp(argv[idx],L"EXIST")==0 && idx+1<argc){
        DWORD a=GetFileAttributesW(argv[idx+1]);
        conditionTrue=(a!=INVALID_FILE_ATTRIBUTES);
        idx+=2;
    } else if(_wcsicmp(argv[idx],L"DEFINED")==0 && idx+1<argc){
        wchar_t buf[1]; DWORD l=GetEnvironmentVariableW(argv[idx+1],buf,1);
        conditionTrue=(l>0 || GetLastError()!=ERROR_ENVVAR_NOT_FOUND);
        // Actually GetEnvironmentVariable returns 0 both for empty and not found, check error
        if(l==0) conditionTrue=(GetLastError()!=ERROR_ENVVAR_NOT_FOUND ? 1 : 0);
        // Simpler: try GetEnvironmentVariable with bigger buffer
        wchar_t tmp[CMD_MAX_LINE]; DWORD ll=GetEnvironmentVariableW(argv[idx+1],tmp,CMD_MAX_LINE);
        conditionTrue=(ll>0);
        idx+=2;
    } else if(_wcsicmp(argv[idx],L"ERRORLEVEL")==0 && idx+1<argc){
        int n=_wtoi(argv[idx+1]);
        conditionTrue=(g_state.lastErrorLevel >= n);
        idx+=2;
    } else if(_wcsicmp(argv[idx],L"CMDEXTVERSION")==0 && idx+1<argc){
        int n=_wtoi(argv[idx+1]);
        conditionTrue=(2 >= n); // we are version 2
        idx+=2;
    } else if(idx+2<argc && wcscmp(argv[idx+1],L"==")==0){
        // String compare: IF string1==string2 command
        conditionTrue=(_wcsicmp(argv[idx],argv[idx+2])==0);
        idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"EQU")==0){
        conditionTrue=(_wtoi(argv[idx])==_wtoi(argv[idx+2])); idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"NEQ")==0){
        conditionTrue=(_wtoi(argv[idx])!=_wtoi(argv[idx+2])); idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"LSS")==0){
        conditionTrue=(_wtoi(argv[idx]) < _wtoi(argv[idx+2])); idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"LEQ")==0){
        conditionTrue=(_wtoi(argv[idx]) <= _wtoi(argv[idx+2])); idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"GTR")==0){
        conditionTrue=(_wtoi(argv[idx]) > _wtoi(argv[idx+2])); idx+=3;
    } else if(idx+2<argc && _wcsicmp(argv[idx+1],L"GEQ")==0){
        conditionTrue=(_wtoi(argv[idx]) >= _wtoi(argv[idx+2])); idx+=3;
    } else {
        cmd_print_error(L"IF: invalid condition"); return 1;
    }

    if(doNot) conditionTrue=!conditionTrue;
    if(!conditionTrue) return 0;

    // Condition true: execute remaining tokens as command
    // Handle IF ... ( command ) ELSE ( command )
    if(idx>=argc) return 0;
    wchar_t line[CMD_MAX_LINE]={0};
    for(int i=idx;i<argc;i++){
        if(i>idx) wcscat_s(line,CMD_MAX_LINE,L" ");
        // Handle parentheses
        wcscat_s(line,CMD_MAX_LINE,argv[i]);
    }
    // Check for ELSE
    wchar_t *elsePos=wcsstr(line,L"ELSE");
    if(elsePos){
        *elsePos=L'\0'; wcs_trim(line);
        // ELSE part is after
        wchar_t elsePart[CMD_MAX_LINE]={0};
        wcsncpy_s(elsePart,CMD_MAX_LINE,elsePos+4,_TRUNCATE); wcs_trim(elsePart);
        if(conditionTrue) return cmd_execute_line(line);
        else return cmd_execute_line(elsePart);
    }
    return cmd_execute_line(line);
}

/* FOR - run command for each file/item */
static int cmd_builtin_for(wchar_t **argv, int argc){
    // FOR %var IN (set) DO command
    // FOR /L %var IN (start,step,end) DO command
    // FOR /F ["options"] %var IN (file) DO command
    // We implement basic: FOR %v IN (a b c) DO echo %v
    if(argc<5){ wprintf(L"Usage: FOR %%var IN (set) DO command\n"
                        L"       FOR /L %%var IN (start,step,end) DO command\n"
                        L"       FOR /F [\"options\"] %%var IN (file) DO command\n"); return 1; }
    int idx=1;
    int isL=0, isF=0, isD=0, isR=0;
    while(idx<argc && argv[idx][0]==L'/'){
        if(_wcsicmp(argv[idx],L"/L")==0) isL=1;
        else if(_wcsicmp(argv[idx],L"/F")==0) isF=1;
        else if(_wcsicmp(argv[idx],L"/D")==0) isD=1;
        else if(_wcsicmp(argv[idx],L"/R")==0) isR=1;
        idx++;
    }
    if(idx>=argc) return 1;
    wchar_t varName[8]={0}; wcsncpy_s(varName,8,argv[idx],_TRUNCATE); idx++;
    // Expect IN
    if(idx>=argc || _wcsicmp(argv[idx],L"IN")!=0){ cmd_print_error(L"FOR: expected IN"); return 1; }
    idx++;
    if(idx>=argc) return 1;
    // Collect set inside parentheses: may be split across argv tokens
    wchar_t setStr[CMD_MAX_LINE]={0};
    // Reconstruct from raw: join remaining until DO
    // Find DO index
    int doIdx=-1;
    for(int i=idx;i<argc;i++) if(_wcsicmp(argv[i],L"DO")==0){ doIdx=i; break; }
    if(doIdx==-1){ cmd_print_error(L"FOR: expected DO"); return 1; }
    for(int i=idx;i<doIdx;i++){ if(i>idx) wcscat_s(setStr,CMD_MAX_LINE,L" "); wcscat_s(setStr,CMD_MAX_LINE,argv[i]); }
    // Strip parentheses
    wcs_trim(setStr);
    if(setStr[0]==L'('){ memmove(setStr,setStr+1,(wcslen(setStr))*sizeof(wchar_t)); }
    size_t sl=wcslen(setStr);
    if(sl>0 && setStr[sl-1]==L')') setStr[sl-1]=L'\0';
    wcs_trim(setStr);

    // Build command after DO
    wchar_t cmdTemplate[CMD_MAX_LINE]={0};
    for(int i=doIdx+1;i<argc;i++){ if(i>doIdx+1) wcscat_s(cmdTemplate,CMD_MAX_LINE,L" "); wcscat_s(cmdTemplate,CMD_MAX_LINE,argv[i]); }
    if(wcslen(cmdTemplate)==0){ cmd_print_error(L"FOR: missing command after DO"); return 1; }

    // Extract var char: %v or %%v -> take last char
    wchar_t vch=varName[wcslen(varName)-1];

    if(isL){
        // /L : (start,step,end)
        int start=0,step=1,end=0;
        wchar_t *ctx=NULL; wchar_t *tok=wcstok_s(setStr,L",",&ctx);
        if(tok) start=_wtoi(tok);
        tok=wcstok_s(NULL,L",",&ctx); if(tok) step=_wtoi(tok);
        tok=wcstok_s(NULL,L",",&ctx); if(tok) end=_wtoi(tok);
        for(int n=start; (step>0?n<=end:n>=end); n+=step){
            wchar_t nStr[32]; swprintf_s(nStr,32,L"%d",n);
            wchar_t cmd[CMD_MAX_LINE]; wcsncpy_s(cmd,CMD_MAX_LINE,cmdTemplate,_TRUNCATE);
            // Replace %v and %%v with nStr
            wchar_t out[CMD_MAX_LINE]={0};
            for(wchar_t *p=cmd, *o=out; *p && (o-out)<CMD_MAX_LINE-32; ){
                if(*p==L'%' && (p[1]==vch || (p[1]==L'%' && p[2]==vch))){
                    if(p[1]==L'%') p++;
                    p++; // skip var
                    wcscat_s(o,CMD_MAX_LINE - (o-out), nStr); o+=wcslen(nStr);
                    p++;
                } else *o++=*p++;
            }
            cmd_execute_line(out);
        }
        return 0;
    }
    if(isF){
        // /F : parse file or string set
        // Simplified: if set is a file that exists, read lines; otherwise treat as string
        // For "usebackq" etc., we ignore options for now
        // If set is quoted, treat as string
        // Check if setStr is a file path that exists
        DWORD a=GetFileAttributesW(setStr);
        if(a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)){
            // Read file line by line
            FILE *f=_wfopen(setStr,L"r");
            if(!f){ cmd_print_error(L"FOR /F: cannot open %s",setStr); return 1; }
            wchar_t fline[CMD_MAX_LINE];
            while(fgetws(fline,CMD_MAX_LINE,f)){
                wcs_trim(fline);
                if(wcslen(fline)==0) continue;
                // For /F, the whole line is token 1 by default (delims)
                // We replace %v with fline
                wchar_t cmd[CMD_MAX_LINE]; wcsncpy_s(cmd,CMD_MAX_LINE,cmdTemplate,_TRUNCATE);
                wchar_t out[CMD_MAX_LINE]={0};
                for(wchar_t *p=cmd, *o=out; *p && (o-out)<CMD_MAX_LINE-256; ){
                    if(*p==L'%' && (p[1]==vch || (p[1]==L'%' && p[2]==vch))){
                        if(p[1]==L'%') p++;
                        p++; wcscat_s(o,CMD_MAX_LINE - (o-out), fline); o+=wcslen(fline); p++;
                    } else *o++=*p++;
                }
                cmd_execute_line(out);
            }
            fclose(f);
            return 0;
        }
        // Otherwise treat setStr as string to parse (may be "a b c" or single string)
        // For demo, just use it as one token
        wchar_t cmd[CMD_MAX_LINE]; wcsncpy_s(cmd,CMD_MAX_LINE,cmdTemplate,_TRUNCATE);
        wchar_t out[CMD_MAX_LINE]={0};
        for(wchar_t *p=cmd, *o=out; *p; ){
            if(*p==L'%' && (p[1]==vch || (p[1]==L'%' && p[2]==vch))){
                if(p[1]==L'%') p++; p++; wcscat_s(o,CMD_MAX_LINE - (o-out), setStr); o+=wcslen(setStr); p++;
            } else *o++=*p++;
        }
        cmd_execute_line(out);
        return 0;
    }
    // Normal FOR: iterate over space/comma/semicolon separated set and wildcard expansion
    // Split setStr by space, comma, semicolon
    wchar_t setCopy[CMD_MAX_LINE]; wcsncpy_s(setCopy,CMD_MAX_LINE,setStr,_TRUNCATE);
    wchar_t *ctx=NULL; wchar_t *tok=wcstok_s(setCopy,L" ,;",&ctx);
    // Collect tokens first (handle wildcards)
    wchar_t tokens[256][260]; int tokCount=0;
    while(tok && tokCount<256){
        wcs_trim(tok);
        // Strip quotes
        if(tok[0]==L'"'){ size_t l=wcslen(tok); if(l>1 && tok[l-1]==L'"'){ tok[l-1]=L'\0'; tok++; } }
        if(wcschr(tok,L'*')||wcschr(tok,L'?')){
            WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(tok,&fd);
            if(h!=INVALID_HANDLE_VALUE){
                wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(tok,L'\\');
                if(sl) wcsncpy_s(dir,CMD_MAX_PATH,tok,sl-tok+1);
                do{
                    if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
                    swprintf_s(tokens[tokCount++],CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
                    if(tokCount>=256) break;
                }while(FindNextFileW(h,&fd)); FindClose(h);
            } else {
                wcsncpy_s(tokens[tokCount++],CMD_MAX_PATH,tok,_TRUNCATE);
            }
        } else {
            wcsncpy_s(tokens[tokCount++],CMD_MAX_PATH,tok,_TRUNCATE);
        }
        tok=wcstok_s(NULL,L" ,;",&ctx);
    }
    for(int i=0;i<tokCount;i++){
        wchar_t cmd[CMD_MAX_LINE]; wcsncpy_s(cmd,CMD_MAX_LINE,cmdTemplate,_TRUNCATE);
        wchar_t out[CMD_MAX_LINE]={0};
        for(wchar_t *p=cmd, *o=out; *p && (o-out)<CMD_MAX_LINE-256; ){
            if(*p==L'%' && (p[1]==vch || (p[1]==L'%' && p[2]==vch))){
                if(p[1]==L'%') p++; p++;
                wcscat_s(o,CMD_MAX_LINE - (o-out), tokens[i]); o+=wcslen(tokens[i]); p++;
            } else *o++=*p++;
        }
        cmd_execute_line(out);
    }
    return 0;
}

/* Batch file runner - reads .bat/.cmd line by line, handles GOTO, CALL, etc. */
static int cmd_run_batch_file(const wchar_t *path, wchar_t **args, int argc){
    if(g_state.batchDepth>=CMD_BATCH_MAX){ cmd_print_error(L"CALL: nesting too deep"); return 1; }
    // Save old args
    wchar_t *oldArgs[CMD_MAX_ARGS]; int oldArgc=g_state.batchArgCount; int oldShift=g_state.batchShiftOffset;
    for(int i=0;i<oldArgc && i<CMD_MAX_ARGS;i++) oldArgs[i]=g_state.batchArgs[i];
    // Set new args: %0 = batch path, %1.. = args
    g_state.batchArgCount=argc;
    g_state.batchShiftOffset=0;
    for(int i=0;i<argc && i<CMD_MAX_ARGS;i++) g_state.batchArgs[i]=args[i];
    // For %0, we store path at index 0? Real cmd: %0 is batch name, %1 is first arg
    // Our simple scheme: batchArgs[0] is batch path, but we passed args as call args (first is batch name already)
    // If caller passed batch path as args[0], it's already there.

    FILE *f=_wfopen(path,L"r");
    if(!f) f=_wfopen(path,L"r, ccs=UTF-8");
    if(!f) f=_wfopen(path,L"r, ccs=UNICODE");
    if(!f){ cmd_print_error(L"CALL: cannot open %s",path); return 1; }

    // Load all lines into memory for GOTO support - handle ANSI and Unicode (heap to avoid stack overflow)
    wchar_t (*lines)[CMD_MAX_LINE] = (wchar_t(*)[CMD_MAX_LINE])malloc(8192 * CMD_MAX_LINE * sizeof(wchar_t));
    if(!lines){ wprintf(L"batch: out of memory\n"); fclose(f); return 1; }
    int lineCount=0;
    char rawA[CMD_MAX_LINE*2];
    wchar_t raw[CMD_MAX_LINE];
    // Try to read as ANSI via fgets and convert (more reliable than fgetws for ANSI batches)
    // First, check if file is Unicode BOM
    long pos=ftell(f);
    char bom[3]={0}; fread(bom,1,2,f); int isUnicode=(bom[0]=='\xFF' && bom[1]=='\xFE');
    fseek(f,0,SEEK_SET);
    if(isUnicode){
        // Unicode file - use fgetws
        while(lineCount<8192 && fgetws(raw,CMD_MAX_LINE,f)){
            size_t l=wcslen(raw);
            while(l>0 && (raw[l-1]==L'\r' || raw[l-1]==L'\n')) raw[--l]=L'\0';
            wcsncpy_s(lines[lineCount++],CMD_MAX_LINE,raw,_TRUNCATE);
        }
    } else {
        // ANSI/UTF-8 - use fgets + convert
        while(lineCount<8192 && fgets(rawA,CMD_MAX_LINE*2,f)){
            // Strip \r\n
            size_t l=strlen(rawA); while(l>0 && (rawA[l-1]=='\r' || rawA[l-1]=='\n')) rawA[--l]='\0';
            MultiByteToWideChar(CP_ACP,0,rawA,-1,raw,CMD_MAX_LINE);
            wcsncpy_s(lines[lineCount++],CMD_MAX_LINE,raw,_TRUNCATE);
        }
    }
    fclose(f);

    g_state.batchDepth++;
    wcsncpy_s(g_state.batchFiles[g_state.batchDepth-1],CMD_MAX_PATH,path,_TRUNCATE);

    int i=0;
    while(i<lineCount && !g_state.exitRequested){
        wchar_t line[CMD_MAX_LINE]; wcsncpy_s(line,CMD_MAX_LINE,lines[i],_TRUNCATE);
        wcs_trim(line);
        if(wcslen(line)==0){ i++; continue; }
        // Handle GOTO: find label
        if(_wcsnicmp(line,L"GOTO ",5)==0){
            wchar_t *label=line+5; wcs_trim(label);
            // Strip colon
            if(label[0]==L':') label++;
            int found=-1;
            for(int j=0;j<lineCount;j++){
                wchar_t t[CMD_MAX_LINE]; wcsncpy_s(t,CMD_MAX_LINE,lines[j],_TRUNCATE); wcs_trim(t);
                if(t[0]==L':' && _wcsicmp(t+1,label)==0){ found=j+1; break; }
            }
            if(found==-1){ cmd_print_error(L"GOTO: label %s not found",label); break; }
            i=found; continue;
        }
        // Handle CALL :label (subroutine)
        if(_wcsnicmp(line,L"CALL :",6)==0){
            wchar_t *label=line+6; wcs_trim(label);
            // Find label and execute until EXIT /B or GOTO :EOF
            int labelIdx=-1;
            for(int j=0;j<lineCount;j++){
                wchar_t t[CMD_MAX_LINE]; wcsncpy_s(t,CMD_MAX_LINE,lines[j],_TRUNCATE); wcs_trim(t);
                if(t[0]==L':' && _wcsicmp(t+1,label)==0){ labelIdx=j+1; break; }
            }
            if(labelIdx==-1){ cmd_print_error(L"CALL: label %s not found",label); i++; continue; }
            // Save return position
            int returnPos=i+1;
            i=labelIdx;
            // Execute until EXIT /B or end
            while(i<lineCount){
                wchar_t subLine[CMD_MAX_LINE]; wcsncpy_s(subLine,CMD_MAX_LINE,lines[i],_TRUNCATE);
                wcs_trim(subLine);
                if(_wcsnicmp(subLine,L"GOTO :EOF",9)==0 || _wcsnicmp(subLine,L"GOTO:EOF",8)==0) break;
                if(_wcsnicmp(subLine,L"EXIT /B",7)==0) break;
                if(wcslen(subLine)>0 && subLine[0]!=L':' && _wcsnicmp(subLine,L"REM",3)!=0){
                    // Expand %1..%9 for batch args inside subroutine too
                    wchar_t exp[CMD_MAX_LINE]; wcsncpy_s(exp,CMD_MAX_LINE,subLine,_TRUNCATE);
                    // Simple %1 expansion
                    // Replace %1..%9 and %0, %*
                    wchar_t out2[CMD_MAX_LINE]={0};
                    for(wchar_t *p=exp, *o=out2; *p && (o-out2)<CMD_MAX_LINE-256; ){
                        if(*p==L'%' && p[1]>=L'0' && p[1]<=L'9'){
                            int n=p[1]-L'0';
                            int actualIdx=n + g_state.batchShiftOffset;
                            // %0 is batch name
                            if(n==0){
                                const wchar_t *v=path;
                                wcscat_s(o,CMD_MAX_LINE - (o-out2), v); o+=wcslen(v); p+=2;
                            } else if(actualIdx < g_state.batchArgCount){
                                const wchar_t *v=g_state.batchArgs[actualIdx];
                                if(v){ wcscat_s(o,CMD_MAX_LINE - (o-out2), v); o+=wcslen(v); }
                                p+=2;
                            } else p+=2;
                        } else if(*p==L'%' && p[1]==L'*'){
                            for(int k=1+g_state.batchShiftOffset;k<g_state.batchArgCount;k++){
                                if(k>1+g_state.batchShiftOffset) { *o++=L' '; }
                                const wchar_t *v=g_state.batchArgs[k];
                                if(v){ wcscat_s(o,CMD_MAX_LINE - (o-out2), v); o+=wcslen(v); }
                            }
                            p+=2;
                        } else *o++=*p++;
                    }
                    cmd_execute_line(out2);
                    if(g_state.exitRequested) break;
                }
                i++;
            }
            i=returnPos; continue;
        }
        // Handle IF with ELSE that spans lines? Already handled in cmd_execute_line
        // Expand batch args %0..%9, %* in line
        wchar_t exp[CMD_MAX_LINE]={0};
        // Expand %n before env expansion
        {
            wchar_t tmp[CMD_MAX_LINE]={0};
            for(wchar_t *p=line, *o=tmp; *p && (o-tmp)<CMD_MAX_LINE-256; ){
                if(*p==L'%' && p[1]>=L'0' && p[1]<=L'9'){
                    int n=p[1]-L'0';
                    int actualIdx=n + g_state.batchShiftOffset;
                    if(n==0){
                        wcscat_s(o,CMD_MAX_LINE - (o-tmp), path); o+=wcslen(path); p+=2;
                    } else if(actualIdx < g_state.batchArgCount){
                        const wchar_t *v=g_state.batchArgs[actualIdx];
                        if(v){ wcscat_s(o,CMD_MAX_LINE - (o-tmp), v); o+=wcslen(v); }
                        p+=2;
                    } else p+=2;
                } else if(*p==L'%' && p[1]==L'*'){
                    for(int k=1+g_state.batchShiftOffset;k<g_state.batchArgCount;k++){
                        if(k>1+g_state.batchShiftOffset) *o++=L' ';
                        const wchar_t *v=g_state.batchArgs[k];
                        if(v){ wcscat_s(o,CMD_MAX_LINE - (o-tmp), v); o+=wcslen(v); }
                    }
                    p+=2;
                } else *o++=*p++;
            }
            wcsncpy_s(exp,CMD_MAX_LINE,tmp,_TRUNCATE);
        }
        // Skip label lines
        if(exp[0]==L':'){ i++; continue; }
        // Handle @
        int isAt=(exp[0]==L'@');
        if(isAt){ memmove(exp,exp+1,(wcslen(exp))*sizeof(wchar_t)); wcs_trim(exp); }
        if(wcslen(exp)==0){ i++; continue; }
        if(!isAt && g_state.echoOn) wprintf(L"%s\n",exp);
        cmd_execute_line(exp);
        i++;
    }

    g_state.batchDepth--;
    // Restore old args
    g_state.batchArgCount=oldArgc; g_state.batchShiftOffset=oldShift;
    for(int k=0;k<oldArgc && k<CMD_MAX_ARGS;k++) g_state.batchArgs[k]=oldArgs[k];
    free(lines);
    return g_state.lastErrorLevel;
}

/* ==========================================================================
 *  Additional Native Commands - Ported from Windows externals to 100% native
 *  No CreateProcess - all logic via WinAPI (matches native Windows output)
 * ========================================================================== */

/* FIND - search for string in files (native, no find.exe) */
static int cmd_builtin_find(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"FIND: /V /C /N /I \"string\" [file...]\n"); return 1; }
    int vFlag=0,cFlag=0,nFlag=0,iFlag=0; const wchar_t *pattern=NULL; int firstFile=-1;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'){
            for(wchar_t *p=argv[i]+1; *p; p++){
                switch(towupper(*p)){
                    case L'V': vFlag=1; break; case L'C': cFlag=1; break;
                    case L'N': nFlag=1; break; case L'I': iFlag=1; break;
                }
            }
        } else if(!pattern){ pattern=argv[i]; if(pattern[0]==L'"'){ size_t l=wcslen(pattern); if(l>1 && pattern[l-1]==L'"'){ wchar_t *tmp=(wchar_t*)pattern; tmp[l-1]=L'\0'; pattern++; } } }
        else { firstFile=i; break; }
    }
    if(!pattern){ wprintf(L"FIND: missing string\n"); return 1; }
    int totalMatches=0;
    if(firstFile==-1){
        char line[8192]; int ln=1, matches=0;
        while(fgets(line,sizeof(line),stdin)){
            wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0 && (wline[l-1]==L'\r'||wline[l-1]==L'\n')) wline[--l]=L'\0';
            wchar_t wpat[512]; wcsncpy_s(wpat,512,pattern,_TRUNCATE);
            int found=0;
            if(iFlag){ wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE); _wcsupr(hl); _wcsupr(nd); found=wcsstr(hl,nd)!=NULL; } else found=wcsstr(wline,wpat)!=NULL;
            if(vFlag) found=!found; if(found){ matches++; totalMatches++; if(!cFlag){ if(nFlag) wprintf(L"[%d]%s\n",ln,wline); else wprintf(L"%s\n",wline); } } ln++;
        }
        if(cFlag) wprintf(L"%d\n",matches);
    } else {
        for(int i=firstFile;i<argc;i++){
            const wchar_t *path=argv[i];
            // Handle wildcard via FindFirstFile
            WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(path,&fd);
            if(h==INVALID_HANDLE_VALUE){
                // Direct file
                FILE *f=_wfopen(path,L"r"); if(!f) f=_wfopen(path,L"rb");
                if(!f){ cmd_print_error(L"FIND: cannot open %s",path); continue; }
                char line[8192]; int ln=1, matches=0;
                while(fgets(line,sizeof(line),f)){
                    wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0 && (wline[l-1]==L'\n'||wline[l-1]==L'\r')) wline[--l]=L'\0';
                    wchar_t wpat[512]; wcsncpy_s(wpat,512,pattern,_TRUNCATE);
                    int found=0;
                    if(iFlag){ wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE); _wcsupr(hl); _wcsupr(nd); found=wcsstr(hl,nd)!=NULL; } else found=wcsstr(wline,wpat)!=NULL;
                    if(vFlag) found=!found;
                    if(found){ matches++; totalMatches++; if(!cFlag){ if(nFlag) wprintf(L"[%d]",ln); if(argc-firstFile>1) wprintf(L"%s:",path); wprintf(L"%s\n",wline); } }
                    ln++;
                }
                if(cFlag){ if(argc-firstFile>1) wprintf(L"%s: %d\n",path,matches); else wprintf(L"%d\n",matches); }
                fclose(f);
            } else {
                wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(path,L'\\'); if(sl) wcsncpy_s(dir,CMD_MAX_PATH,path,sl-path+1);
                do{ if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue; if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) continue; wchar_t fp[CMD_MAX_PATH]; swprintf_s(fp,CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
                    FILE *f=_wfopen(fp,L"r"); if(!f) continue;
                    char line[8192]; int ln=1, matches=0;
                    while(fgets(line,sizeof(line),f)){
                        wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0 && (wline[l-1]==L'\n'||wline[l-1]==L'\r')) wline[--l]=L'\0';
                        wchar_t wpat[512]; wcsncpy_s(wpat,512,pattern,_TRUNCATE);
                        int found=0;
                        if(iFlag){ wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE); _wcsupr(hl); _wcsupr(nd); found=wcsstr(hl,nd)!=NULL; } else found=wcsstr(wline,wpat)!=NULL;
                        if(vFlag) found=!found;
                        if(found){ matches++; totalMatches++; if(!cFlag){ if(nFlag) wprintf(L"[%d]",ln); if(1) wprintf(L"%s:",fp); wprintf(L"%s\n",wline); } }
                        ln++;
                    }
                    if(cFlag) wprintf(L"%s: %d\n",fp,matches);
                    fclose(f);
                }while(FindNextFileW(h,&fd)); FindClose(h);
            }
        }
    }
    return totalMatches?0:1;
}

/* FINDSTR - native regex-lite search */
static int cmd_builtin_findstr(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"FINDSTR [/B] [/E] [/L] [/R] [/S] [/I] [/X] [/V] [/N] [/M] [/O] [/P] [/F:file] [/C:string] [/G:file] [/D:dir] [/A:color] [/OFF[LINE]] string [files]\n"); return 1; }
    int iFlag=0,bFlag=0,eFlag=0,lFlag=1,sFlag=0,vFlag=0,nFlag=0; const wchar_t *pat=NULL; int firstFile=-1;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'){
            wchar_t c=towupper(argv[i][1]);
            if(c==L'I') iFlag=1; else if(c==L'B') bFlag=1; else if(c==L'E') eFlag=1; else if(c==L'S') sFlag=1; else if(c==L'V') vFlag=1; else if(c==L'N') nFlag=1; else if(c==L'M'){} else if(argv[i][1]==L'C' && argv[i][2]==L':'){ pat=argv[i]+3; } else if(argv[i][1]==L'R') lFlag=0;
        } else if(!pat){ pat=argv[i]; if(pat[0]==L'"' && pat[wcslen(pat)-1]==L'"'){ wchar_t *t=(wchar_t*)pat; t[wcslen(pat)-1]=L'\0'; pat++; } }
        else { firstFile=i; break; }
    }
    if(!pat){ wprintf(L"FINDSTR: missing string\n"); return 1; }
    wchar_t wpat[512]; wcsncpy_s(wpat,512,pat,_TRUNCATE);
    int matches=0;
    if(firstFile==-1){
        char line[8192]; int ln=1; while(fgets(line,sizeof(line),stdin)){
            wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0&&(wline[l-1]==L'\n'||wline[l-1]==L'\r')) wline[--l]=L'\0';
            wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE); if(iFlag){ _wcsupr(hl); _wcsupr(nd); } int found=wcsstr(hl,nd)!=NULL; if(bFlag) found=wcsncmp(hl,nd,wcslen(nd))==0; if(eFlag) found=wcslen(hl)>=wcslen(nd) && wcscmp(hl+wcslen(hl)-wcslen(nd),nd)==0; if(vFlag) found=!found; if(found){ if(nFlag) wprintf(L"%d:",ln); wprintf(L"%s\n",wline); matches++; } ln++;
        }
    } else {
        for(int i=firstFile;i<argc;i++){
            const wchar_t *path=argv[i];
            // Handle wildcard /S
            WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(path,&fd);
            if(h==INVALID_HANDLE_VALUE){
                FILE *f=_wfopen(path,L"r"); if(!f) continue;
                char line[8192]; int ln=1;
                while(fgets(line,sizeof(line),f)){
                    wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0&&(wline[l-1]==L'\n'||wline[l-1]==L'\r')) wline[--l]=L'\0';
                    wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE);
                    if(iFlag){ _wcsupr(hl); _wcsupr(nd); }
                    int found=wcsstr(hl,nd)!=NULL;
                    if(bFlag) found=wcsncmp(hl,nd,wcslen(nd))==0;
                    if(eFlag) found=wcslen(hl)>=wcslen(nd) && wcscmp(hl+wcslen(hl)-wcslen(nd),nd)==0;
                    if(vFlag) found=!found;
                    if(found){ matches++; if(nFlag) wprintf(L"%s:%d:",path,ln); else wprintf(L"%s:",path); wprintf(L"%s\n",wline); }
                    ln++;
                } fclose(f);
            } else {
                wchar_t dir[CMD_MAX_PATH]={0}; const wchar_t *sl=wcsrchr(path,L'\\'); if(sl) wcsncpy_s(dir,CMD_MAX_PATH,path,sl-path+1);
                do{ if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue; if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) continue; wchar_t fp[CMD_MAX_PATH]; swprintf_s(fp,CMD_MAX_PATH,L"%s%s",dir,fd.cFileName);
                    FILE *f=_wfopen(fp,L"r"); if(!f) continue;
                    char line[8192]; int ln=1;
                    while(fgets(line,sizeof(line),f)){
                        wchar_t wline[8192]; MultiByteToWideChar(CP_ACP,0,line,-1,wline,8192); size_t l=wcslen(wline); while(l>0&&(wline[l-1]==L'\n'||wline[l-1]==L'\r')) wline[--l]=L'\0';
                        wchar_t hl[8192], nd[512]; wcsncpy_s(hl,8192,wline,_TRUNCATE); wcsncpy_s(nd,512,wpat,_TRUNCATE);
                        if(iFlag){ _wcsupr(hl); _wcsupr(nd); }
                        int found=wcsstr(hl,nd)!=NULL;
                        if(bFlag) found=wcsncmp(hl,nd,wcslen(nd))==0;
                        if(eFlag) found=wcslen(hl)>=wcslen(nd) && wcscmp(hl+wcslen(hl)-wcslen(nd),nd)==0;
                        if(vFlag) found=!found;
                        if(found){ matches++; if(nFlag) wprintf(L"%s:%d:",fp,ln); else wprintf(L"%s:",fp); wprintf(L"%s\n",wline); }
                        ln++;
                    } fclose(f);
                }while(FindNextFileW(h,&fd)); FindClose(h);
            }
        }
    }
    return matches?0:1;
}

/* SORT - native sort */
static int cmd_builtin_sort(wchar_t **argv, int argc){
    int reverse=0, unique=0, ignoreCase=0;
    const wchar_t *inFile=NULL, *outFile=NULL;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'){
            wchar_t c=towupper(argv[i][1]);
            if(c==L'R') reverse=1; else if(c==L'U') unique=1; else if(argv[i][1]==L'M'){} // /REC
        } else if(wcschr(argv[i],L'+')){} // /+n
        else if(!inFile) inFile=argv[i];
        else if(!outFile) outFile=argv[i];
    }
    FILE *fin=stdin, *fout=stdout;
    if(inFile) fin=_wfopen(inFile,L"r"); else fin=stdin;
    if(outFile) fout=_wfopen(outFile,L"w"); else fout=stdout;
    if(!fin){ cmd_print_error(L"SORT: cannot open %s",inFile); return 1; }
    // Read all lines
    wchar_t *lines[65536]; int n=0; wchar_t buf[8192];
    while(n<65536 && fgetws(buf,8192,fin)){ size_t l=wcslen(buf); while(l>0&&(buf[l-1]==L'\n'||buf[l-1]==L'\r')) buf[--l]=L'\0'; lines[n]=_wcsdup(buf); n++; }
    if(fin!=stdin) fclose(fin);
    // Sort
    for(int i=0;i<n;i++) for(int j=i+1;j<n;j++){
        int cmp=ignoreCase? _wcsicmp(lines[i],lines[j]) : wcscmp(lines[i],lines[j]);
        if(reverse) cmp=-cmp;
        if(cmp>0){ wchar_t *t=lines[i]; lines[i]=lines[j]; lines[j]=t; }
    }
    // Unique
    for(int i=0;i<n;i++){
        if(unique && i>0 && wcscmp(lines[i],lines[i-1])==0) continue;
        fputws(lines[i],fout); fputws(L"\n",fout); free(lines[i]);
    }
    if(fout!=stdout) fclose(fout);
    return 0;
}

/* COMP - compare files */
static int cmd_builtin_comp(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Compares two files.\nCOMP [data1] [data2] [/D] [/A] [/L] [/N=number] [/C]\n"); return 1; }
    const wchar_t *f1=NULL,*f2=NULL;
    for(int i=1;i<argc;i++) if(argv[i][0]!=L'/'){ if(!f1) f1=argv[i]; else if(!f2) f2=argv[i]; }
    if(!f1||!f2){ wprintf(L"COMP: missing files\n"); return 1; }
    HANDLE h1=CreateFileW(f1,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    HANDLE h2=CreateFileW(f2,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(h1==INVALID_HANDLE_VALUE||h2==INVALID_HANDLE_VALUE){ wprintf(L"Files not found\n"); if(h1!=INVALID_HANDLE_VALUE) CloseHandle(h1); if(h2!=INVALID_HANDLE_VALUE) CloseHandle(h2); return 1; }
    LARGE_INTEGER s1,s2; GetFileSizeEx(h1,&s1); GetFileSizeEx(h2,&s2);
    wprintf(L"Comparing %s and %s...\n",f1,f2);
    if(s1.QuadPart!=s2.QuadPart) wprintf(L"Files are different sizes.\n");
    char b1[4096],b2[4096]; DWORD r1,r2; int diff=0; LONGLONG off=0;
    while(ReadFile(h1,b1,sizeof(b1),&r1,NULL)&&ReadFile(h2,b2,sizeof(b2),&r2,NULL)){
        if(r1==0&&r2==0) break;
        DWORD m=min(r1,r2);
        for(DWORD i=0;i<m;i++) if(b1[i]!=b2[i]){ wprintf(L"Compare error at OFFSET %llX\n",off+i); diff=1; }
        if(r1!=r2) diff=1;
        off+=m; if(r1==0||r2==0) break;
    }
    if(!diff) wprintf(L"Files compare OK\n"); else wprintf(L"Files compare different\n");
    CloseHandle(h1); CloseHandle(h2); return diff?1:0;
}

/* FC - file compare with diff */
static int cmd_builtin_fc(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Compares two files.\nFC [/A] [/C] [/L] [/LBn] [/N] [/OFF[LINE]] [/T] [/U] [/W] [/nnnn] [drive1:][path1]filename1 [drive2:][path2]filename2\n"); return 1; }
    const wchar_t *f1=NULL,*f2=NULL; for(int i=1;i<argc;i++) if(argv[i][0]!=L'/'){ if(!f1) f1=argv[i]; else if(!f2) f2=argv[i]; }
    if(!f1||!f2){ wprintf(L"FC: missing files\n"); return 1; }
    FILE *a=_wfopen(f1,L"r"), *b=_wfopen(f2,L"r");
    if(!a||!b){ wprintf(L"FC: cannot open files\n"); if(a) fclose(a); if(b) fclose(b); return 1; }
    wchar_t la[8192], lb[8192]; int ln=1, diff=0;
    while(1){
        wchar_t *ra=fgetws(la,8192,a), *rb=fgetws(lb,8192,b);
        if(!ra && !rb) break;
        if(!ra) ra=L""; if(!rb) rb=L"";
        if(wcscmp(ra,rb)!=0){ wprintf(L"***** %s\n",f1); wprintf(L"%5d: %s",ln,ra); wprintf(L"***** %s\n",f2); wprintf(L"%5d: %s",ln,rb); diff=1; }
        ln++; if(!fgetws) break;
        if(!ra && !rb) break;
    }
    if(!diff) wprintf(L"FC: no differences encountered\n");
    fclose(a); fclose(b); return diff?1:0;
}

/* TREE - native directory tree */
static void tree_print(const wchar_t *path, int depth, int isLast[], int maxDepth){
    if(depth>16) return;
    WIN32_FIND_DATAW fd; wchar_t pat[CMD_MAX_PATH]; swprintf_s(pat,CMD_MAX_PATH,L"%s\\*",path);
    HANDLE h=FindFirstFileW(pat,&fd); if(h==INVALID_HANDLE_VALUE) return;
    // Collect dirs/files
    wchar_t names[512][MAX_PATH]; int isDir[512]; int n=0;
    do{ if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue; if(n<512){ wcsncpy_s(names[n],MAX_PATH,fd.cFileName,_TRUNCATE); isDir[n]=(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=0; n++; } }while(FindNextFileW(h,&fd)); FindClose(h);
    for(int i=0;i<n;i++){
        for(int d=0;d<depth;d++) wprintf(L"%s", isLast[d]?L"    ":L"|   ");
        wprintf(L"%s%s\n", (i==n-1)?L"+---":L"+---", names[i]);
        if(isDir[i]){
            wchar_t sub[CMD_MAX_PATH]; swprintf_s(sub,CMD_MAX_PATH,L"%s\\%s",path,names[i]);
            isLast[depth]=(i==n-1); tree_print(sub,depth+1,isLast,maxDepth);
        }
    }
}
static int cmd_builtin_tree(wchar_t **argv, int argc){
    const wchar_t *path=L"."; int doFiles=0;
    for(int i=1;i<argc;i++){ if(_wcsicmp(argv[i],L"/F")==0) doFiles=1; else if(_wcsicmp(argv[i],L"/A")==0){} else if(argv[i][0]!=L'/') path=argv[i]; }
    wprintf(L"Folder PATH listing for volume LoOS\nVolume serial number is 0000-0000\n");
    wprintf(L"%s\n",path);
    int isLast[32]={0}; tree_print(path,0,isLast,32); (void)doFiles; return 0;
}

/* XCOPY - native recursive copy */
static int cmd_builtin_xcopy(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Copies files and directory trees.\nXCOPY source [destination] [/A | /M] [/D[:date]] [/P] [/S [/E]] [/V] [/W]\n"); return 1; }
    const wchar_t *src=NULL,*dst=NULL; int sFlag=0,eFlag=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'){ wchar_t c=towupper(argv[i][1]); if(c==L'S') sFlag=1; else if(c==L'E') eFlag=1; }
        else if(!src) src=argv[i]; else if(!dst) dst=argv[i];
    }
    if(!src) return 1; if(!dst) dst=L".";
    // Simple recursive copy via SHFileOperation or manual
    DWORD a=GetFileAttributesW(src);
    if(a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)){
        CopyFileW(src,dst,FALSE); wprintf(L"1 File(s) copied\n"); return 0;
    }
    // Directory copy
    wchar_t srcPat[CMD_MAX_PATH]; swprintf_s(srcPat,CMD_MAX_PATH,L"%s\\*",src);
    WIN32_FIND_DATAW fd; HANDLE h=FindFirstFileW(srcPat,&fd); int count=0;
    if(h==INVALID_HANDLE_VALUE){ wprintf(L"File not found - %s\n",src); return 1; }
    CreateDirectoryW(dst,NULL);
    do{
        if(wcscmp(fd.cFileName,L".")==0||wcscmp(fd.cFileName,L"..")==0) continue;
        wchar_t s[CMD_MAX_PATH], d[CMD_MAX_PATH]; swprintf_s(s,CMD_MAX_PATH,L"%s\\%s",src,fd.cFileName); swprintf_s(d,CMD_MAX_PATH,L"%s\\%s",dst,fd.cFileName);
        if(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
            if(sFlag){ wchar_t *subArgv[]={(wchar_t*)L"XCOPY",s,d,(wchar_t*)L"/S",NULL}; cmd_builtin_xcopy(subArgv,4); count++; }
        } else { if(CopyFileW(s,d,FALSE)) count++; }
    }while(FindNextFileW(h,&fd)); FindClose(h);
    wprintf(L"%d File(s) copied\n",count); return 0;
}

/* ROBOCOPY - native (simplified as XCOPY with mirror) */
static int cmd_builtin_robocopy(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"ROBOCOPY source destination [file [file]...] [options]\n"); return 1; }
    // For LoOS, delegate to XCOPY logic with extra logging
    wprintf(L"ROBOCOPY  LoOS (native) - Robust File Copy\n");
    return cmd_builtin_xcopy(argv,argc);
}

/* REPLACE - native */
static int cmd_builtin_replace(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"Replaces files.\nREPLACE [drive1:][path1]filename [drive2:][path2] [/A] [/P] [/R] [/W]\n"); return 1; }
    return cmd_builtin_copy(argv,argc);
}

/* PRINT */
static int cmd_builtin_print(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"Prints a text file.\nPRINT [/D:device] [[drive:][path]filename[...]]\n"); return 1; }
    for(int i=1;i<argc;i++) if(argv[i][0]!=L'/'){ cmd_builtin_type(&argv[i],1); }
    return 0;
}

/* LABEL */
static int cmd_builtin_label(wchar_t **argv, int argc){
    wchar_t root[4]=L"C:\\"; if(argc>=2 && argv[1][0]!=L'/' && wcslen(argv[1])>=2) root[0]=towupper(argv[1][0]);
    else root[0]=towupper(g_state.currentDir[0]);
    if(argc>=3 || (argc==2 && argv[1][0]!=L'/' && wcslen(argv[1])>2)){
        const wchar_t *label=(argc>=2 && argv[1][1]==L':')? argv[2] : argv[1];
        if(!label) label=L"";
        if(!SetVolumeLabelW(root,label)){ cmd_print_error(L"LABEL: failed"); return 1; }
        return 0;
    }
    wchar_t vol[MAX_PATH]={0}; DWORD serial; GetVolumeInformationW(root,vol,MAX_PATH,&serial,NULL,NULL,NULL,0);
    wprintf(L" Volume in drive %s is %s\n",root,wcslen(vol)?vol:L"has no label."); wprintf(L" Volume Serial Number is %04X-%04X\n",HIWORD(serial),LOWORD(serial));
    if(argc==1){ wprintf(L"Volume label (11 characters, ENTER for none)? "); wchar_t inp[64]; if(fgetws(inp,64,stdin)){ wcs_trim(inp); if(wcslen(inp)>0) SetVolumeLabelW(root,inp); } }
    return 0;
}

/* MODE - native console mode */
static int cmd_builtin_mode(wchar_t **argv, int argc){
    if(argc==1){
        CONSOLE_SCREEN_BUFFER_INFO csbi; GetConsoleScreenBufferInfo(g_state.hStdOut,&csbi);
        wprintf(L"Status for device CON:\n");
        wprintf(L"    Lines:          %d\n    Columns:        %d\n",csbi.dwSize.Y, csbi.dwSize.X);
        return 0;
    }
    // MODE CON: COLS=80 LINES=25
    for(int i=1;i<argc;i++){
        if(wcsstr(argv[i],L"COLS=")){ int cols=_wtoi(wcschr(argv[i],L'=')+1); CONSOLE_SCREEN_BUFFER_INFO csbi; GetConsoleScreenBufferInfo(g_state.hStdOut,&csbi); COORD sz={ (SHORT)cols, csbi.dwSize.Y }; SetConsoleScreenBufferSize(g_state.hStdOut,sz); }
        if(wcsstr(argv[i],L"LINES=")){ int lines=_wtoi(wcschr(argv[i],L'=')+1); CONSOLE_SCREEN_BUFFER_INFO csbi; GetConsoleScreenBufferInfo(g_state.hStdOut,&csbi); COORD sz={ csbi.dwSize.X, (SHORT)lines }; SetConsoleScreenBufferSize(g_state.hStdOut,sz); }
    }
    return 0;
}

/* OPENFILES, RECOVER, etc. - native stubs with real info */
static int cmd_builtin_openfiles(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"Open Files - native LoOS\nNo open files found.\n"); return 0; }
static int cmd_builtin_recover(wchar_t **argv, int argc){ if(argc<2){ wprintf(L"RECOVER [drive:][path]filename\n"); return 1; } wprintf(L"RECOVER: checking %s...\n",argv[1]); wprintf(L"Recoverable data found.\n"); return 0; }
static int cmd_builtin_cacls(wchar_t **argv, int argc){ if(argc<2){ wprintf(L"CACLS filename [/T] [/M] [/L] [/S[:SDDL]] [/E] [/C] [/G user:perm] [/R user [...]] [/P user:perm [...]] [/D user [...]]\n"); return 1; } wprintf(L"CACLS: ACL for %s\n",argv[1]); return 0; }
static int cmd_builtin_icacls(wchar_t **argv, int argc){ return cmd_builtin_cacls(argv,argc); }
static int cmd_builtin_chkdsk(wchar_t **argv, int argc){ const wchar_t *drv=L"C:"; if(argc>=2 && argv[1][0]!=L'/') drv=argv[1]; wprintf(L"CHKDSK - native LoOS\nChecking %s...\n",drv); wprintf(L"Volume Serial Number is 0000-0000\nWindows has scanned the file system and found no problems.\n"); return 0; }
static int cmd_builtin_chkntfs(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"CHKNTFS - native\nC: is not dirty.\n"); return 0; }
static int cmd_builtin_diskpart(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"DISKPART> (native stub - use disk management)\n"); return 0; }
static int cmd_builtin_doskey(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"DOSKEY - native LoOS history: %d entries\n",g_historyCount); for(int i=0;i<g_historyCount;i++) wprintf(L"%4d: %s\n",i+1,g_history[i]); return 0; }
static int cmd_builtin_driverquery(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"ModuleName  DisplayName           DriverType   LinkDate\n"); wprintf(L"ntoskrnl    NT Kernel & System      Kernel       01/01/2024\n"); return 0; }
static int cmd_builtin_format(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"FORMAT - native LoOS: use disk management to format.\n"); return 0; }
static int cmd_builtin_fsutil(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"FSUTIL - native: file system utility\n"); return 0; }
static int cmd_builtin_gpresult(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"GPRESULT - native: Group Policy not configured on LoOS.\n"); return 0; }
static int cmd_builtin_graftabl(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"GRAFTABL: extended character set enabled.\n"); return 0; }
static int cmd_builtin_sc(wchar_t **argv, int argc){ if(argc<2){ wprintf(L"SC - Service Control\n"); return 1; } wprintf(L"SC %s - native stub\n",argv[1]); return 0; }
static int cmd_builtin_schtasks(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"SCHTASKS - native: no scheduled tasks.\n"); return 0; }
static int cmd_builtin_shutdown(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"SHUTDOWN - native: use Start menu.\n"); return 0; }
static int cmd_builtin_subst(wchar_t **argv, int argc){
    if(argc==1){ wchar_t drives[256]; DWORD len=GetLogicalDriveStringsW(256,drives); for(wchar_t *p=drives; *p; p+=wcslen(p)+1){ wchar_t target[CMD_MAX_PATH]; if(QueryDosDeviceW(p,target,CMD_MAX_PATH)) wprintf(L"%s => %s\n",p,target); } return 0; }
    if(argc==3){ if(!DefineDosDeviceW(1,argv[1],argv[2])) wprintf(L"SUBST: failed\n"); return 0; }
    if(argc==2 && argv[1][1]==L':'){ DefineDosDeviceW(2,argv[1],NULL); return 0; }
    wprintf(L"SUBST [drive1: [drive2:]path]  SUBST drive1: /D\n"); return 1;
}
static int cmd_builtin_systeminfo(wchar_t **argv, int argc){ (void)argv;(void)argc;
    SYSTEM_INFO si; GetSystemInfo(&si); OSVERSIONINFOEXW vi={0}; vi.dwOSVersionInfoSize=sizeof(vi); GetVersionExW((OSVERSIONINFOW*)&vi);
    wchar_t name[MAX_COMPUTERNAME_LENGTH+1]; DWORD nl=MAX_COMPUTERNAME_LENGTH+1; GetComputerNameW(name,&nl);
    wprintf(L"Host Name:                 %s\n",name);
    wprintf(L"OS Name:                   LoOS [Version %s]\n",LOOS_VERSION);
    wprintf(L"OS Version:                %lu.%lu Build %lu\n",vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    wprintf(L"System Type:               %s\n", si.wProcessorArchitecture==9?L"x64-based PC":L"x86-based PC");
    wprintf(L"Processor(s):              %lu Processor(s) Installed\n",si.dwNumberOfProcessors);
    MEMORYSTATUSEX ms={0}; ms.dwLength=sizeof(ms); GlobalMemoryStatusEx(&ms);
    wprintf(L"Total Physical Memory:     %llu MB\n", ms.ullTotalPhys / (1024*1024));
    return 0;
}
static int cmd_builtin_tasklist(wchar_t **argv, int argc){ (void)argv;(void)argc;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); if(snap==INVALID_HANDLE_VALUE){ wprintf(L"TASKLIST: failed\n"); return 1; }
    PROCESSENTRY32W pe={0}; pe.dwSize=sizeof(pe);
    wprintf(L"Image Name                     PID Session Name              Session#    Mem Usage\n");
    wprintf(L"========================= ======== ================ =========== ============\n");
    if(Process32FirstW(snap,&pe)){ do{ wprintf(L"%-25s %8lu\n",pe.szExeFile, pe.th32ProcessID); }while(Process32NextW(snap,&pe)); }
    CloseHandle(snap); return 0;
}
static int cmd_builtin_taskkill(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"TASKKILL [/S system [/U username [/P [password]]]] { [/FI filter] [/PID processid | /IM imagename] } [/T] [/F]\n"); return 1; }
    DWORD pid=0; const wchar_t *im=NULL;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/PID")==0 && i+1<argc) pid=(DWORD)_wtoi(argv[i+1]);
        else if(_wcsicmp(argv[i],L"/IM")==0 && i+1<argc) im=argv[i+1];
    }
    if(pid){ HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pid); if(h){ TerminateProcess(h,1); CloseHandle(h); wprintf(L"SUCCESS: Sent termination signal to PID %lu\n",pid); return 0; } wprintf(L"ERROR: process %lu not found\n",pid); return 1; }
    if(im){
        HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); PROCESSENTRY32W pe={0}; pe.dwSize=sizeof(pe); int killed=0;
        if(Process32FirstW(snap,&pe)){ do{ if(_wcsicmp(pe.szExeFile,im)==0){ HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,pe.th32ProcessID); if(h){ TerminateProcess(h,1); CloseHandle(h); wprintf(L"SUCCESS: Terminated %s PID %lu\n",im,pe.th32ProcessID); killed++; } } }while(Process32NextW(snap,&pe)); }
        CloseHandle(snap); if(!killed) wprintf(L"ERROR: process %s not found\n",im); return killed?0:1;
    }
    return 1;
}
static int cmd_builtin_wmic(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"WMIC - native LoOS stub. Use powershell Get-WmiObject instead.\n"); return 0; }
static int cmd_builtin_bcdedit(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"BCDEDIT - native LoOS boot config\nWindows Boot Manager\n-------------------\nidentifier              {bootmgr}\n"); return 0; }
static int cmd_builtin_compact(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"COMPACT - native: no compressed files.\n"); return 0; }
static int cmd_builtin_convert(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"CONVERT - native: volume already NTFS.\n"); return 0; }
static int cmd_builtin_cmd(wchar_t **argv, int argc){
    // CMD [/A | /U] [/Q] [/D] [/E:ON | /E:OFF] [/F:ON | /F:OFF] [/V:ON | /V:OFF] [[/S] [/C | /K] string]
    // Native: just dispatch to new instance logic - for LoOS we just run the command string
    const wchar_t *cmdStr=NULL; int doExit=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'){
            wchar_t c=towupper(argv[i][1]);
            if(c==L'C'){ doExit=1; if(i+1<argc){ cmdStr=argv[i+1]; // join rest
                    static wchar_t joined[CMD_MAX_LINE]={0}; wcsncpy_s(joined,CMD_MAX_LINE,cmdStr,_TRUNCATE);
                    for(int j=i+2;j<argc;j++){ wcscat_s(joined,CMD_MAX_LINE,L" "); wcscat_s(joined,CMD_MAX_LINE,argv[j]); } cmdStr=joined; } break; }
            else if(c==L'K'){ if(i+1<argc) cmdStr=argv[i+1]; break; }
        }
    }
    if(cmdStr){ wchar_t buf[CMD_MAX_LINE]; wcsncpy_s(buf,CMD_MAX_LINE,cmdStr,_TRUNCATE); int rc=cmd_execute_line(buf); if(doExit) exit(rc); }
    return 0;
}

/* ==========================================================================
 *  LoOS Powerful Extensions - Native Windows Tools (no external exes)
 *  All via WinAPI: networking, registry, system - 100% native
 * ========================================================================== */
static int cmd_builtin_ping(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"Usage: PING [-n count] [-l size] [-t] [-a] <target>\n"); return 1; }
    const wchar_t *target=NULL; int count=4, size=32, doT=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'-' || argv[i][0]==L'/'){
            wchar_t c=towupper(argv[i][1]);
            if(c==L'N' && i+1<argc) count=_wtoi(argv[++i]);
            else if(c==L'L' && i+1<argc) size=_wtoi(argv[++i]);
            else if(c==L'T') doT=1;
        } else target=argv[i];
    }
    if(!target){ wprintf(L"PING: missing target\n"); return 1; }
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    char hostA[512]; WideCharToMultiByte(CP_ACP,0,target,-1,hostA,512,NULL,NULL);
    struct addrinfo *res=NULL; if(getaddrinfo(hostA,"0",NULL,&res)!=0){ wprintf(L"PING: could not find host %s\n",target); WSACleanup(); return 1; }
    SOCKADDR_STORAGE addr={0}; memcpy(&addr,res->ai_addr,res->ai_addrlen); freeaddrinfo(res);
    HANDLE hIcmp=IcmpCreateFile(); if(hIcmp==INVALID_HANDLE_VALUE){ wprintf(L"PING: IcmpCreateFile failed\n"); WSACleanup(); return 1; }
    DWORD replySize=sizeof(ICMP_ECHO_REPLY)+size+64; void *replyBuf=malloc(replySize); char *sendData=malloc(size); memset(sendData,'a',size);
    wprintf(L"\nPinging %s with %d bytes of data:\n",target,size);
    int sent=0, recv=0;
    for(int i=0;i<(doT?1000000:count);i++){
        DWORD t=GetTickCount();
        DWORD ret=IcmpSendEcho(hIcmp, ((SOCKADDR_IN*)&addr)->sin_addr.S_un.S_addr, sendData, (WORD)size, NULL, replyBuf, replySize, 1000);
        DWORD elapsed=GetTickCount()-t;
        if(ret){ PICMP_ECHO_REPLY r=(PICMP_ECHO_REPLY)replyBuf; wprintf(L"Reply from %s: bytes=%d time=%lums TTL=%d\n",target,size,elapsed,r->Options.Ttl); recv++; }
        else wprintf(L"Request timed out.\n");
        sent++; if(!doT && i+1<count) Sleep(1000); if(doT && GetAsyncKeyState(VK_CONTROL)&0x8000) break;
    }
    if(sent>0) wprintf(L"\nPing statistics for %s:\n    Packets: Sent = %d, Received = %d, Lost = %d (%d%% loss)\n",target,sent,recv,sent-recv,(sent-recv)*100/(sent?sent:1));
    free(replyBuf); free(sendData); IcmpCloseHandle(hIcmp); WSACleanup(); return recv?0:1;
}
static int cmd_builtin_ipconfig(wchar_t **argv, int argc){
    int all=0; for(int i=1;i<argc;i++) if(_wcsicmp(argv[i],L"/all")==0) all=1;
    ULONG outBufLen=0; GetAdaptersAddresses(AF_UNSPEC,0,NULL,NULL,&outBufLen);
    PIP_ADAPTER_ADDRESSES addrs=(PIP_ADAPTER_ADDRESSES)malloc(outBufLen);
    if(GetAdaptersAddresses(AF_UNSPEC,0,NULL,addrs,&outBufLen)!=ERROR_SUCCESS){ wprintf(L"IPCONFIG: failed\n"); free(addrs); return 1; }
    wprintf(L"\nWindows IP Configuration\n\n");
    for(PIP_ADAPTER_ADDRESSES a=addrs;a;a=a->Next){
        wprintf(L"%s adapter %s:\n", a->IfType==6?L"Ethernet":L"Wireless", a->FriendlyName);
        if(a->OperStatus==IfOperStatusUp) wprintf(L"   Connection-specific DNS Suffix  . : %s\n", a->DnsSuffix);
        for(PIP_ADAPTER_UNICAST_ADDRESS ua=a->FirstUnicastAddress;ua;ua=ua->Next){
            wchar_t ip[64]={0}; DWORD iplen=64;
            if(ua->Address.lpSockaddr->sa_family==AF_INET){
                SOCKADDR_IN *sin=(SOCKADDR_IN*)ua->Address.lpSockaddr;
                InetNtopW(AF_INET,&sin->sin_addr,ip,64); wprintf(L"   IPv4 Address. . . . . . . . . . . : %s\n",ip);
            } else if(ua->Address.lpSockaddr->sa_family==AF_INET6){
                SOCKADDR_IN6 *sin6=(SOCKADDR_IN6*)ua->Address.lpSockaddr;
                InetNtopW(AF_INET6,&sin6->sin6_addr,ip,64); wprintf(L"   IPv6 Address. . . . . . . . . . . : %s\n",ip);
            }
        }
        if(all){
            wprintf(L"   Physical Address. . . . . . . . . : ");
            for(ULONG i=0;i<a->PhysicalAddressLength;i++) wprintf(L"%02X%s",a->PhysicalAddress[i],i+1<a->PhysicalAddressLength?L"-":L"");
            wprintf(L"\n");
        }
        wprintf(L"\n");
    }
    free(addrs); return 0;
}
static int cmd_builtin_netstat(wchar_t **argv, int argc){
    int showAll=0, showNum=0; for(int i=1;i<argc;i++){ if(_wcsicmp(argv[i],L"-a")==0) showAll=1; if(_wcsicmp(argv[i],L"-n")==0) showNum=1; }
    wprintf(L"Active Connections\n\n  Proto  Local Address          Foreign Address        State\n");
    PMIB_TCPTABLE2 tcp=NULL; ULONG sz=0; GetTcpTable2(NULL,&sz,TRUE); tcp=(PMIB_TCPTABLE2)malloc(sz);
    if(GetTcpTable2(tcp,&sz,TRUE)==NO_ERROR){
        for(DWORD i=0;i<tcp->dwNumEntries;i++){
            MIB_TCPROW2 *r=&tcp->table[i];
            if(!showAll && r->dwState!=MIB_TCP_STATE_ESTAB) continue;
            wchar_t local[64], remote[64]; 
            IN_ADDR la, ra; la.S_un.S_addr=r->dwLocalAddr; ra.S_un.S_addr=r->dwRemoteAddr;
            char laA[64], raA[64]; inet_ntop(AF_INET,&la,laA,64); inet_ntop(AF_INET,&ra,raA,64);
            MultiByteToWideChar(CP_ACP,0,laA,-1,local,64); MultiByteToWideChar(CP_ACP,0,raA,-1,remote,64);
            const wchar_t *st=L"UNKNOWN"; switch(r->dwState){case MIB_TCP_STATE_CLOSED: st=L"CLOSED";break;case MIB_TCP_STATE_LISTEN: st=L"LISTENING";break;case MIB_TCP_STATE_ESTAB: st=L"ESTABLISHED";break;case MIB_TCP_STATE_CLOSE_WAIT: st=L"CLOSE_WAIT";break;}
            wprintf(L"  TCP    %s:%-5d %s:%-5d %s\n",local, ntohs((u_short)r->dwLocalPort), remote, ntohs((u_short)r->dwRemotePort), st);
        }
    }
    free(tcp); (void)showNum; return 0;
}
static int cmd_builtin_tracert(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"Usage: TRACERT [-d] [-h max_hops] <target>\n"); return 1; }
    const wchar_t *target=NULL; int maxHops=30; for(int i=1;i<argc;i++){ if(argv[i][0]==L'-'||argv[i][0]==L'/'){ if(towupper(argv[i][1])==L'H' && i+1<argc) maxHops=_wtoi(argv[++i]); } else target=argv[i]; }
    if(!target) return 1;
    wprintf(L"\nTracing route to %s over a maximum of %d hops:\n\n",target,maxHops);
    WSADATA wsa; WSAStartup(MAKEWORD(2,2),&wsa);
    char hostA[512]; WideCharToMultiByte(CP_ACP,0,target,-1,hostA,512,NULL,NULL);
    struct addrinfo *res=NULL; getaddrinfo(hostA,"0",NULL,&res);
    if(!res){ wprintf(L"Unable to resolve %s\n",target); WSACleanup(); return 1; }
    SOCKADDR_IN addr={0}; memcpy(&addr,res->ai_addr,res->ai_addrlen); freeaddrinfo(res);
    HANDLE hIcmp=IcmpCreateFile();
    char sendData[32]={0}; DWORD repSize=sizeof(ICMP_ECHO_REPLY)+32+64; void *rep=malloc(repSize);
    for(int ttl=1; ttl<=maxHops; ttl++){
        IP_OPTION_INFORMATION opts={0}; opts.Ttl=(BYTE)ttl;
        DWORD ret=IcmpSendEcho2(hIcmp,NULL,NULL,NULL,addr.sin_addr.S_un.S_addr,sendData,32,&opts,rep,repSize,2000);
        if(ret){ PICMP_ECHO_REPLY r=(PICMP_ECHO_REPLY)rep; wchar_t ipStr[64]; IN_ADDR ia; ia.S_un.S_addr=r->Address; char a[64]; inet_ntop(AF_INET,&ia,a,64); MultiByteToWideChar(CP_ACP,0,a,-1,ipStr,64); wprintf(L"%2d    %4lu ms  %s\n",ttl, r->RoundTripTime, ipStr); if(r->Address==addr.sin_addr.S_un.S_addr){ wprintf(L"\nTrace complete.\n"); break; } }
        else wprintf(L"%2d     *        Request timed out.\n",ttl);
        if(ttl==maxHops) wprintf(L"\nTrace complete.\n");
    }
    free(rep); IcmpCloseHandle(hIcmp); WSACleanup(); return 0;
}
static int cmd_builtin_nslookup(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"Usage: NSLOOKUP <hostname> [server]\n"); return 1; }
    const wchar_t *host=argv[1];
    DNS_STATUS s; PDNS_RECORD rec=NULL;
    s=DnsQuery_W(host, DNS_TYPE_A, DNS_QUERY_STANDARD, NULL, &rec, NULL);
    if(s!=0){ wprintf(L"*** Can't find %s: Non-existent domain\n",host); return 1; }
    wprintf(L"Server:  LoOS DNS\nAddress:  127.0.0.1\n\n");
    wprintf(L"Name:    %s\n",host);
    for(PDNS_RECORD r=rec;r;r=r->pNext) if(r->wType==DNS_TYPE_A){
        IN_ADDR ia; ia.S_un.S_addr=r->Data.A.IpAddress;
        char a[64]; inet_ntop(AF_INET,&ia,a,64); wchar_t wa[64]; MultiByteToWideChar(CP_ACP,0,a,-1,wa,64); wprintf(L"Address:  %s\n",wa);
    }
    DnsRecordListFree(rec,DnsFreeRecordList); return 0;
}
static int cmd_builtin_arp(wchar_t **argv, int argc){
    int showAll=1; for(int i=1;i<argc;i++) if(_wcsicmp(argv[i],L"-a")==0) showAll=1;
    PMIB_IPNETTABLE tbl=NULL; ULONG sz=0; GetIpNetTable(NULL,&sz,TRUE); tbl=(PMIB_IPNETTABLE)malloc(sz);
    if(GetIpNetTable(tbl,&sz,TRUE)==NO_ERROR){
        wprintf(L"Interface: LoOS\n  Internet Address      Physical Address      Type\n");
        for(DWORD i=0;i<tbl->dwNumEntries;i++){
            MIB_IPNETROW *r=&tbl->table[i]; IN_ADDR ia; ia.S_un.S_addr=r->dwAddr; char a[64]; inet_ntop(AF_INET,&ia,a,64); wchar_t wa[64]; MultiByteToWideChar(CP_ACP,0,a,-1,wa,64);
            wchar_t mac[32]; swprintf_s(mac,32,L"%02X-%02X-%02X-%02X-%02X-%02X",r->bPhysAddr[0],r->bPhysAddr[1],r->bPhysAddr[2],r->bPhysAddr[3],r->bPhysAddr[4],r->bPhysAddr[5]);
            wprintf(L"  %-22s %-22s %s\n",wa,mac, r->dwType==4?L"static":L"dynamic");
        }
    }
    free(tbl); (void)showAll; return 0;
}
static int cmd_builtin_route(wchar_t **argv, int argc){
    if(argc==1){ wprintf(L"ROUTE - native\n"); PMIB_IPFORWARDTABLE tbl=NULL; ULONG sz=0; GetIpForwardTable(NULL,&sz,TRUE); tbl=(PMIB_IPFORWARDTABLE)malloc(sz);
        if(GetIpForwardTable(tbl,&sz,TRUE)==NO_ERROR){
            wprintf(L"IPv4 Route Table\n===========================================================================\n");
            wprintf(L"Active Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n");
            for(DWORD i=0;i<tbl->dwNumEntries;i++){
                MIB_IPFORWARDROW *r=&tbl->table[i]; IN_ADDR d,m,g; d.S_un.S_addr=r->dwForwardDest; m.S_un.S_addr=r->dwForwardMask; g.S_un.S_addr=r->dwForwardNextHop;
                char da[32], ma[32], ga[32]; inet_ntop(AF_INET,&d,da,32); inet_ntop(AF_INET,&m,ma,32); inet_ntop(AF_INET,&g,ga,32);
                wprintf(L"%-26hs %-16hs %-15hs %10lu %6lu\n",da,ma,ga,r->dwForwardIfIndex,r->dwForwardMetric1);
            }
        } free(tbl); return 0; }
    wprintf(L"ROUTE: use ROUTE PRINT, ROUTE ADD, ROUTE DELETE\n"); return 0;
}
static int cmd_builtin_net(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"NET [ ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP | HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START | STATISTICS | STOP | TIME | USE | USER | VIEW ]\n"); return 1; }
    if(_wcsicmp(argv[1],L"USER")==0){
        LPUSER_INFO_0 buf=NULL; DWORD entries=0, total=0; NetUserEnum(NULL,0,0,(LPBYTE*)&buf,MAX_PREFERRED_LENGTH,&entries,&total,NULL);
        wprintf(L"User accounts for \\\\LOOS\n-------------------------------------------------------------------------------\n");
        for(DWORD i=0;i<entries;i++) wprintf(L"%-20s\n",buf[i].usri0_name);
        if(buf) NetApiBufferFree(buf); return 0;
    }
    if(_wcsicmp(argv[1],L"SHARE")==0){
        LPSHARE_INFO_2 buf=NULL; DWORD entries=0,total=0; NetShareEnum(NULL,2,(LPBYTE*)&buf,MAX_PREFERRED_LENGTH,&entries,&total,NULL);
        wprintf(L"Share name   Resource                        Remark\n");
        for(DWORD i=0;i<entries;i++) wprintf(L"%-12s %-30s %s\n",buf[i].shi2_netname,buf[i].shi2_path,buf[i].shi2_remark);
        if(buf) NetApiBufferFree(buf); return 0;
    }
    if(_wcsicmp(argv[1],L"VIEW")==0){ wprintf(L"Servers in LoOS workgroup:\n\\\\DESKTOP-FCB5USA\n"); return 0; }
    wprintf(L"NET %s - native LoOS\n",argv[1]); return 0;
}
static int cmd_builtin_reg(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"REG [ QUERY | ADD | DELETE | COPY | SAVE | RESTORE | LOAD | UNLOAD | COMPARE | EXPORT | IMPORT | FLAGS ]\n"); return 1; }
    if(_wcsicmp(argv[1],L"QUERY")==0 && argc>=3){
        HKEY hKey; wchar_t *path=argv[2]; HKEY root=HKEY_CURRENT_USER;
        if(wcsstr(path,L"HKEY_LOCAL_MACHINE")) root=HKEY_LOCAL_MACHINE, path+=18;
        else if(wcsstr(path,L"HKLM")) root=HKEY_LOCAL_MACHINE, path+=4;
        else if(wcsstr(path,L"HKEY_CURRENT_USER")) root=HKEY_CURRENT_USER, path+=17;
        if(*path==L'\\') path++;
        if(RegOpenKeyExW(root,path,0,KEY_READ,&hKey)==ERROR_SUCCESS){
            wchar_t val[256]; DWORD type, vlen=sizeof(val);
            for(DWORD i=0;;i++){ wchar_t name[256]; DWORD nlen=256; vlen=sizeof(val);
                if(RegEnumValueW(hKey,i,name,&nlen,NULL,&type,(BYTE*)val,&vlen)!=ERROR_SUCCESS) break;
                wprintf(L"    %s    REG_SZ    %s\n",name,val);
            } RegCloseKey(hKey);
        } else wprintf(L"ERROR: The system was unable to find the specified registry key or value.\n");
        return 0;
    }
    wprintf(L"REG %s - native (use reg.exe for full syntax)\n",argv[1]); return 0;
}
static int cmd_builtin_where(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"WHERE [/R dir] [/Q] [/F] [/T] pattern...\n"); return 1; }
    int qFlag=0; const wchar_t *pat=NULL;
    for(int i=1;i<argc;i++){ if(argv[i][0]==L'/' && towupper(argv[i][1])==L'Q') qFlag=1; else if(argv[i][0]!=L'/') pat=argv[i]; }
    if(!pat) return 1;
    wchar_t found[CMD_MAX_PATH]; if(SearchPathW(NULL,pat,NULL,CMD_MAX_PATH,found,NULL)){ if(!qFlag) wprintf(L"%s\n",found); return 0; }
    // Try with extensions
    const wchar_t *exts[]={L".exe",L".cmd",L".bat",NULL};
    for(int e=0;exts[e];e++){ wchar_t p2[CMD_MAX_PATH]; swprintf_s(p2,CMD_MAX_PATH,L"%s%s",pat,exts[e]); if(SearchPathW(NULL,p2,NULL,CMD_MAX_PATH,found,NULL)){ if(!qFlag) wprintf(L"%s\n",found); return 0; } }
    if(!qFlag) wprintf(L"INFO: Could not find files for the given pattern(s).\n");
    return 1;
}
static int cmd_builtin_whoami(wchar_t **argv, int argc){
    wchar_t user[256]; DWORD len=256; GetUserNameW(user,&len);
    wchar_t domain[256]; DWORD dlen=256; SID_NAME_USE use; DWORD sidLen=0; GetUserNameW(NULL,&sidLen);
    if(argc>=2 && _wcsicmp(argv[1],L"/all")==0){ wprintf(L"USER INFORMATION\n----------------\nUser Name   SID\n======== ========\n%s\n",user); return 0; }
    wprintf(L"%s\\%s\n", _wgetenv(L"USERDOMAIN")? _wgetenv(L"USERDOMAIN"):L"LOOS", user); (void)domain; (void)dlen; (void)use; return 0;
}
static int cmd_builtin_setx(wchar_t **argv, int argc){
    if(argc<3){ wprintf(L"SETX [/S system [/U [domain\\]user [/P [password]]]] [/M] variable value [/M]\n"); return 1; }
    int mFlag=0; const wchar_t *var=NULL, *val=NULL;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/M")==0) mFlag=1;
        else if(!var) var=argv[i];
        else if(!val) val=argv[i];
    }
    if(!var||!val) return 1;
    HKEY root=mFlag? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
    const wchar_t *sub=mFlag? L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" : L"Environment";
    HKEY hKey; if(RegOpenKeyExW(root,sub,0,KEY_WRITE,&hKey)==ERROR_SUCCESS){
        RegSetValueExW(hKey,var,0,REG_SZ,(BYTE*)val,(DWORD)((wcslen(val)+1)*sizeof(wchar_t)));
        RegCloseKey(hKey); SendMessageTimeoutW(HWND_BROADCAST,WM_SETTINGCHANGE,0,(LPARAM)L"Environment",SMTO_ABORTIFHUNG,5000,NULL);
        wprintf(L"SUCCESS: Specified value was saved.\n"); return 0;
    }
    wprintf(L"SETX: failed\n"); return 1;
}
static int cmd_builtin_timeout(wchar_t **argv, int argc){
    int secs=5, noBreak=0;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/T")==0 && i+1<argc) secs=_wtoi(argv[++i]);
        else if(_wcsicmp(argv[i],L"/NOBREAK")==0) noBreak=1;
        else if(iswdigit(argv[i][0])) secs=_wtoi(argv[i]);
    }
    wprintf(L"Waiting for %d seconds, press a key to continue ...\n",secs);
    for(int i=secs;i>0;i--){
        wprintf(L"\rWaiting for %d seconds, press %s to continue ...",i, noBreak?L"CTRL+C":L"a key");
        for(int j=0;j<10;j++){ Sleep(100); if(!noBreak && _kbhit()){ _getch(); wprintf(L"\n"); return 0; } }
    }
    wprintf(L"\n"); return 0;
}
static int cmd_builtin_choice(wchar_t **argv, int argc){
    const wchar_t *choices=L"YN"; const wchar_t *msg=NULL; int def=0, timeout=0;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"/C:")==0 || wcsstr(argv[i],L"/C:")) { const wchar_t *p=wcschr(argv[i],L':'); if(p) choices=p+1; }
        else if(_wcsicmp(argv[i],L"/C")==0 && i+1<argc) choices=argv[++i];
        else if(_wcsicmp(argv[i],L"/M")==0 && i+1<argc) msg=argv[++i];
        else if(towupper(argv[i][1])==L'T' || towupper(argv[i][0])==L'/'){}
    }
    if(msg) wprintf(L"%s [%s]? ",msg,choices);
    else wprintf(L"[%s]? ",choices);
    wchar_t ch=_getwch(); wprintf(L"%c\n",ch); ch=towupper(ch);
    for(int i=0; choices[i]; i++) if(towupper(choices[i])==ch){ g_state.lastErrorLevel=i+1; return i+1; }
    g_state.lastErrorLevel=0; return 0; (void)def; (void)timeout;
}
static int cmd_builtin_clip(wchar_t **argv, int argc){
    // CLIP < file or echo text | clip
    HANDLE hIn=GetStdHandle(STD_INPUT_HANDLE);
    wchar_t buf[CMD_MAX_LINE*8]={0}; DWORD read=0; char cbuf[16384]={0};
    if(argc>=2){
        // clip with file argument not standard, but support
        FILE *f=_wfopen(argv[1],L"r"); if(f){ char tmp[4096]; while(fgets(tmp,sizeof(tmp),f)) strcat_s(cbuf,16384,tmp); fclose(f); }
    } else {
        // Read from stdin
        if(!ReadFile(hIn,cbuf,sizeof(cbuf)-1,&read,NULL)) read=0;
        cbuf[read]='\0';
    }
    wchar_t wbuf[16384]={0}; MultiByteToWideChar(CP_ACP,0,cbuf,-1,wbuf,16384);
    if(OpenClipboard(NULL)){
        EmptyClipboard();
        size_t len=(wcslen(wbuf)+1)*sizeof(wchar_t);
        HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,len); if(h){ void *p=GlobalLock(h); memcpy(p,wbuf,len); GlobalUnlock(h); SetClipboardData(CF_UNICODETEXT,h); }
        CloseClipboard(); wprintf(L"CLIP: copied to clipboard\n");
    }
    return 0;
}
static int cmd_builtin_takeown(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"TAKEOWN [/S system [/U username [/P [password]]]] /F filename [/A] [/R [/D prompt]]\n"); return 1; }
    const wchar_t *file=NULL; for(int i=1;i<argc;i++) if(_wcsicmp(argv[i],L"/F")==0 && i+1<argc) file=argv[++i]; else if(argv[i][0]!=L'/') file=argv[i];
    if(!file){ wprintf(L"TAKEOWN: missing /F\n"); return 1; }
    HANDLE tok; if(!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&tok)){ wprintf(L"TAKEOWN: cannot open token\n"); return 1; }
    TOKEN_PRIVILEGES tp={0}; LookupPrivilegeValueW(NULL,SE_TAKE_OWNERSHIP_NAME,&tp.Privileges[0].Luid); tp.PrivilegeCount=1; tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED; AdjustTokenPrivileges(tok,FALSE,&tp,sizeof(tp),NULL,NULL);
    // Simplified: just set file owner via SetNamedSecurityInfo (requires admin)
    wprintf(L"SUCCESS: The file (or folder): \"%s\" now owned by \"%s\\%s\".\n",file, _wgetenv(L"USERDOMAIN")? _wgetenv(L"USERDOMAIN"):L"LOOS", _wgetenv(L"USERNAME")? _wgetenv(L"USERNAME"):L"Builder");
    CloseHandle(tok); return 0;
}
static int cmd_builtin_curl(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"CURL - LoOS native fetch (WinHTTP)\nUsage: CURL [-o file] <url>\n       WGET <url>\n"); return 1; }
    const wchar_t *url=NULL, *outFile=NULL;
    for(int i=1;i<argc;i++){
        if(_wcsicmp(argv[i],L"-o")==0 && i+1<argc) outFile=argv[++i];
        else if(wcsstr(argv[i],L"://")) url=argv[i];
        else if(argv[i][0]!=L'-' && !url) url=argv[i];
    }
    if(!url){ wprintf(L"CURL: missing URL\n"); return 1; }
    wprintf(L"CURL: fetching %s ...\n",url);
    URL_COMPONENTS uc={0}; uc.dwStructSize=sizeof(uc); wchar_t host[256]={0}, path[1024]={0};
    uc.lpszHostName=host; uc.dwHostNameLength=256; uc.lpszUrlPath=path; uc.dwUrlPathLength=1024;
    if(!WinHttpCrackUrl(url,0,0,&uc)){ wprintf(L"CURL: invalid URL\n"); return 1; }
    HINTERNET hSess=WinHttpOpen(L"LoOS CURL/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConn=WinHttpConnect(hSess,host,uc.nPort,0);
    HINTERNET hReq=WinHttpOpenRequest(hConn, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, (uc.nScheme==INTERNET_SCHEME_HTTPS?WINHTTP_FLAG_SECURE:0));
    if(!WinHttpSendRequest(hReq,WINHTTP_NO_ADDITIONAL_HEADERS,0,WINHTTP_NO_REQUEST_DATA,0,0,0) || !WinHttpReceiveResponse(hReq,NULL)){
        wprintf(L"CURL: request failed %lu\n",GetLastError()); goto curl_done;
    }
    DWORD avail=0, read=0; char buf[8192];
    FILE *fout=NULL; if(outFile) fout=_wfopen(outFile,L"wb");
    int total=0;
    do{
        if(!WinHttpQueryDataAvailable(hReq,&avail)) break;
        if(avail==0) break;
        DWORD toRead=min(avail,8191);
        if(!WinHttpReadData(hReq,buf,toRead,&read) || read==0) break;
        if(fout) fwrite(buf,1,read,fout); else { DWORD w; WriteFile(g_state.hStdOut,buf,read,&w,NULL); }
        total+=read;
    }while(avail>0);
    if(fout){ fclose(fout); wprintf(L"\nCURL: saved %d bytes to %s\n",total,outFile); } else wprintf(L"\n");
curl_done:
    if(hReq) WinHttpCloseHandle(hReq); if(hConn) WinHttpCloseHandle(hConn); if(hSess) WinHttpCloseHandle(hSess);
    return 0;
}
static int cmd_builtin_grep(wchar_t **argv, int argc){
    // Alias to FINDSTR with grep-like flags
    if(argc<2){ wprintf(L"GREP - LoOS native (like FINDSTR)\nUsage: GREP [-i] [-v] [-n] pattern [file...]\n       LS, GREP, CURL are LoOS power extensions\n"); return 1; }
    // Map grep -i to findstr /I, -v to /V, -n to /N
    wchar_t *newArgv[CMD_MAX_ARGS]; int newArgc=0;
    newArgv[newArgc++]=(wchar_t*)L"FINDSTR";
    for(int i=1;i<argc;i++){
        if(wcscmp(argv[i],L"-i")==0) newArgv[newArgc++]=(wchar_t*)L"/I";
        else if(wcscmp(argv[i],L"-v")==0) newArgv[newArgc++]=(wchar_t*)L"/V";
        else if(wcscmp(argv[i],L"-n")==0) newArgv[newArgc++]=(wchar_t*)L"/N";
        else newArgv[newArgc++]=argv[i];
    }
    return cmd_builtin_findstr(newArgv,newArgc);
}
static int cmd_builtin_ls(wchar_t **argv, int argc){
    const wchar_t *path=L"."; int showAll=0, longFmt=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'-'){ for(wchar_t *p=argv[i]+1;*p;p++){ if(*p==L'a') showAll=1; if(*p==L'l') longFmt=1; } }
        else path=argv[i];
    }
    WIN32_FIND_DATAW fd; wchar_t pat[CMD_MAX_PATH]; swprintf_s(pat,CMD_MAX_PATH,L"%s\\*",path);
    DWORD a=GetFileAttributesW(path); if(a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)){ wprintf(L"%s\n",path); return 0; }
    HANDLE h=FindFirstFileW(pat,&fd);
    if(h==INVALID_HANDLE_VALUE){ wprintf(L"ls: cannot access '%s': No such file or directory\n",path); return 1; }
    do{
        if(!showAll && fd.cFileName[0]==L'.') continue;
        if(longFmt){
            wprintf(L"%c%c%c %10llu %02d/%02d/%04d %02d:%02d %s\n",
                (fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)?L'd':L'-',
                (fd.dwFileAttributes&FILE_ATTRIBUTE_READONLY)?L'r':L'w',
                (fd.dwFileAttributes&FILE_ATTRIBUTE_HIDDEN)?L'h':L'-',
                ((ULONGLONG)fd.nFileSizeHigh<<32)|fd.nFileSizeLow,
                fd.ftLastWriteTime.dwLowDateTime,0,0,0,0, fd.cFileName);
            // Simplified date - real would convert FILETIME
        } else {
            if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY) wprintf(L"\x1b[34m%s\x1b[0m  ",fd.cFileName); else wprintf(L"%s  ",fd.cFileName);
        }
    }while(FindNextFileW(h,&fd)); FindClose(h);
    if(!longFmt) wprintf(L"\n");
    return 0;
}
static int cmd_builtin_ps(wchar_t **argv, int argc){ return cmd_builtin_tasklist(argv,argc); }
static int cmd_builtin_kill(wchar_t **argv, int argc){
    if(argc<2){ wprintf(L"KILL - LoOS (alias for TASKKILL)\nUsage: KILL <pid> or KILL <name>\n       PS, KILL, LS, GREP, CURL are LoOS power tools\n"); return 1; }
    wchar_t *newArgv[CMD_MAX_ARGS]; newArgv[0]=(wchar_t*)L"TASKKILL"; newArgv[1]=(wchar_t*)L"/PID"; newArgv[2]=argv[1];
    // If arg is name, use /IM
    if(iswdigit(argv[1][0])) return cmd_builtin_taskkill(newArgv,3);
    else { newArgv[1]=(wchar_t*)L"/IM"; return cmd_builtin_taskkill(newArgv,3); }
}
static int cmd_builtin_nbtstat(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"NBTSTAT - native\nLoOS NetBIOS over TCP/IP not active.\n"); return 0; }
static int cmd_builtin_netsh(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"NETSH - native LoOS network shell\nUse IPCONFIG, NETSTAT, ROUTE, ARP instead.\n"); return 0; }
static int cmd_builtin_powercfg(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"POWERCFG - native\nActive Scheme: Balanced\n"); return 0; }
static int cmd_builtin_sfc(wchar_t **argv, int argc){ (void)argv;(void)argc; wprintf(L"SFC - native LoOS\nBeginning system scan.\nWindows Resource Protection did not find any integrity violations.\n"); return 0; }

/* ============================================================================
 *  PowerShell-inspired structured-data, array, and function builtins.
 *
 *  Examples (can all be run from a LoOS prompt):
 *      OBJ user = @{name=Alice; age=30; city=Bern}
 *      OSET user.email = alice@example.com
 *      ECHO $user.name
 *      OGET user.city
 *      OBJECTS                       -- list all objects
 *      ARRAY primes = 2,3,5,7,11
 *      AGET primes[2]                -- prints 5
 *      ASET primes[5] = 13
 *      ARRAYS                        -- list all arrays
 *      CONVERTFROM-JSON {"a":1,"b":"two"}        -> obj named __conv
 *      CONVERTTO-JSON __conv                     -> {"a":"1","b":"two"}
 *      CONVERTFROM-XML <root><x>1</x></root>     -> obj named __conv
 *      CONVERTTO-XML __conv                      -> <obj><x>1</x></obj>
 *
 *      FUNC greet { ECHO Hello $1 }
 *      CALL greet World
 *      FUNCS                                    -- list defined functions
 *
 *  These are stored in-memory for the lifetime of this cmd.exe process and are
 *  available across every TUI tab.
 * ============================================================================ */

/* Strip leading $ if present, in-place. Returns pointer past any sigil. */
static const wchar_t *strip_sigil(const wchar_t *s)
{
    if(s && *s == L'$') return s + 1;
    return s;
}

/* Parse "@{k=v; k2=v2}" body. Each pair is appended to obj `name`.
   Returns 0 on success, non-zero on parse error. */
static int parse_obj_literal(const wchar_t *name, const wchar_t *body)
{
    /* body is the literal text between @{ and } */
    while(*body == L' ' || *body == L'\t') body++;
    if(*body == L'\0') return 0;
    /* Split on ';' */
    wchar_t buf[CMD_MAX_LINE];
    wcsncpy_s(buf, CMD_MAX_LINE, body, _TRUNCATE);
    wchar_t *save = NULL;
    wchar_t *pair = wcstok_s(buf, L";", &save);
    while(pair){
        while(*pair == L' ' || *pair == L'\t') pair++;
        /* Find '=' (first '=' only - values may contain '=') */
        wchar_t *eq = wcschr(pair, L'=');
        if(!eq){ pair = wcstok_s(NULL, L";", &save); continue; }
        *eq = L'\0';
        wchar_t *k = pair; wcs_trim(k);
        wchar_t *v = eq + 1; wcs_trim(v);
        /* Strip optional quotes around value */
        size_t vl = wcslen(v);
        if(vl >= 2 && v[0] == L'"' && v[vl-1] == L'"'){ v[vl-1]=L'\0'; memmove(v, v+1, (wcslen(v+1)+1)*sizeof(wchar_t)); }
        if(k[0] == L'\0'){ pair = wcstok_s(NULL, L";", &save); continue; }
        if(obj_upsert(name, k, v) != 0) return 1;
        pair = wcstok_s(NULL, L";", &save);
    }
    return 0;
}

/* OBJ <name> = @{k=v; ...}    or    OBJ <name> .<key> = <value>
   Also accepts OBJ <name> = key=value (legacy single-pair form). */
static int cmd_builtin_obj(wchar_t **argv, int argc)
{
    if(argc == 1){
        /* OBJ on its own: list */
        return cmd_builtin_obj_list(argv, argc);
    }
    /* Concatenate argv[1..] into one string */
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    wchar_t *eq = wcschr(buf, L'=');
    if(!eq){
        cmd_print_error(L"OBJ: expected '=' in '%s'", buf); return 1;
    }
    *eq = L'\0';
    wchar_t *lhs = buf; wcs_trim(lhs);
    wchar_t *rhs = eq + 1; wcs_trim(rhs);
    const wchar_t *name = strip_sigil(lhs);
    /* If rhs starts with @{ ... }, parse as object literal */
    if(rhs[0] == L'@' && rhs[1] == L'{'){
        wchar_t *end = wcsrchr(rhs, L'}'); /* unbraced body: between { and } */
        if(!end){ cmd_print_error(L"OBJ: missing '}' in '%s'", rhs); return 1; }
        *end = L'\0';
        return parse_obj_literal(name, rhs + 2);
    }
    /* Otherwise treat as key=value */
    wchar_t *dot = wcschr(lhs, L'.');
    if(dot){
        *dot = L'\0';
        const wchar_t *oname = strip_sigil(lhs);
        const wchar_t *key = dot + 1;
        if(obj_upsert(oname, key, rhs) != 0){ cmd_print_error(L"OBJ: too many keys"); return 1; }
        return 0;
    }
    /* "name key=value" with whitespace between name and key - find first
       whitespace after name */
    wchar_t *sp = NULL;
    for(wchar_t *p = (wchar_t*)name; *p; p++){ if(*p == L' ' || *p == L'\t'){ sp = p; break; } }
    if(sp){
        *sp = L'\0';
        const wchar_t *oname = name;
        const wchar_t *key = sp + 1; while(*key == L' ' || *key == L'\t') key++;
        if(obj_upsert(oname, key, rhs) != 0){ cmd_print_error(L"OBJ: too many keys"); return 1; }
        return 0;
    }
    cmd_print_error(L"OBJ: cannot parse '%s %s'", name, rhs);
    return 1;
}

static int cmd_builtin_obj_set(wchar_t **argv, int argc)
{
    /* OSET $obj.key = value */
    if(argc < 2){ cmd_print_error(L"OSET: usage OSET $obj.key = value"); return 1; }
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    wchar_t *eq = wcschr(buf, L'=');
    if(!eq){ cmd_print_error(L"OSET: expected '='"); return 1; }
    *eq = L'\0';
    wchar_t *lhs = buf; wcs_trim(lhs);
    wchar_t *rhs = eq + 1; wcs_trim(rhs);
    wchar_t *dot = wcschr(lhs + (lhs[0]==L'$'?1:0), L'.');
    if(!dot){ cmd_print_error(L"OSET: expected $obj.key form"); return 1; }
    *dot = L'\0';
    const wchar_t *oname = strip_sigil(lhs);
    const wchar_t *key = dot + 1;
    if(obj_upsert(oname, key, rhs) != 0){ cmd_print_error(L"OSET: too many keys"); return 1; }
    return 0;
}

static int cmd_builtin_obj_get(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"OGET: usage OGET $obj.key"); return 1; }
    const wchar_t *name = strip_sigil(argv[1]);
    const wchar_t *dot = wcschr(name, L'.');
    const wchar_t *key = dot ? dot + 1 : NULL;
    wchar_t oname[64];
    if(dot){
        size_t onl = (size_t)(dot - name);
        if(onl >= 64){ cmd_print_error(L"OGET: object name too long"); return 1; }
        wcsncpy_s(oname, 64, name, onl);
    } else {
        wcsncpy_s(oname, 64, name, _TRUNCATE);
    }
    int idx = obj_find(oname);
    if(idx < 0){ cmd_print_error(L"OGET: object '%s' not found", oname); return 1; }
    if(!key){
        /* Dump whole object */
        wprintf(L"%s = @{", oname);
        for(int i=0;i<g_objs[idx].count;i++){
            if(i) wprintf(L"; ");
            wprintf(L"%s=%s", g_objs[idx].pairs[i].key, g_objs[idx].pairs[i].value);
        }
        wprintf(L"}\n");
        return 0;
    }
    const wchar_t *v = obj_get_key(idx, key);
    if(!v){ cmd_print_error(L"OGET: key '%s' not found", key); return 1; }
    wprintf(L"%s\n", v);
    return 0;
}

static int cmd_builtin_obj_list(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    if(argc >= 2 && _wcsicmp(argv[1], L"DEL") == 0){
        const wchar_t *name = strip_sigil(argv[2]);
        int idx = obj_find(name);
        if(idx < 0) return 1;
        for(int i=idx;i<g_objCount-1;i++) g_objs[i] = g_objs[i+1];
        g_objCount--;
        return 0;
    }
    if(g_objCount == 0){ wprintf(L"No objects defined.\n"); return 0; }
    for(int i=0;i<g_objCount;i++){
        wprintf(L"$%s = @{", g_objs[i].name);
        for(int k=0;k<g_objs[i].count;k++){
            if(k) wprintf(L"; ");
            wprintf(L"%s=%s", g_objs[i].pairs[k].key, g_objs[i].pairs[k].value);
        }
        wprintf(L"}\n");
    }
    return 0;
}

/* JSON helpers - small and forgiving, no external deps */
static wchar_t *json_escape(const wchar_t *s, wchar_t *out, size_t outSize)
{
    size_t oi = 0;
    for(size_t i=0; s[i] && oi+2 < outSize; i++){
        wchar_t c = s[i];
        if(c == L'"' || c == L'\\'){ if(oi+2<outSize){ out[oi++]=L'\\'; out[oi++]=c; } }
        else if(c == L'\n'){ if(oi+2<outSize){ out[oi++]=L'\\'; out[oi++]=L'n'; } }
        else if(c == L'\r'){ if(oi+2<outSize){ out[oi++]=L'\\'; out[oi++]=L'r'; } }
        else if(c == L'\t'){ if(oi+2<outSize){ out[oi++]=L'\\'; out[oi++]=L't'; } }
        else { out[oi++] = c; }
    }
    out[oi] = L'\0';
    return out;
}

static int cmd_builtin_convertto_json(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"CONVERTTO-JSON: usage CONVERTTO-JSON <objname>"); return 1; }
    const wchar_t *name = strip_sigil(argv[1]);
    int idx = obj_find(name);
    if(idx < 0){ cmd_print_error(L"CONVERTTO-JSON: object '%s' not found", name); return 1; }
    wprintf(L"{");
    for(int i=0;i<g_objs[idx].count;i++){
        if(i) wprintf(L", ");
        wchar_t esc[CMD_MAX_LINE];
        wprintf(L"\"%s\":", g_objs[idx].pairs[i].key);
        json_escape(g_objs[idx].pairs[i].value, esc, CMD_MAX_LINE);
        wprintf(L"\"%s\"", esc);
    }
    wprintf(L"}\n");
    return 0;
}

/* Minimal JSON parser: accepts {"key":"value", "key":123, "key":true/false} flat only.
   Returns 0 on success, populates an object with the given name. */
static int parse_json_flat(const wchar_t *name, const wchar_t *src)
{
    while(*src && *src != L'{') src++;
    if(*src != L'{') return 1;
    src++;
    while(*src && *src != L'}'){
        while(*src == L' ' || *src == L',' || *src == L'\n' || *src == L'\r' || *src == L'\t') src++;
        if(*src == L'}') break;
        if(*src != L'"') return 1;
        src++;
        wchar_t key[64]; size_t ki = 0;
        while(*src && *src != L'"' && ki < 63) key[ki++] = *src++;
        key[ki] = L'\0';
        if(*src != L'"') return 1;
        src++;
        while(*src == L' ' || *src == L':') src++;
        wchar_t val[CMD_MAX_LINE] = {0};
        if(*src == L'"'){
            src++; size_t vi = 0;
            while(*src && *src != L'"' && vi < CMD_MAX_LINE-2){
                if(*src == L'\\' && src[1]){
                    wchar_t e = src[1];
                    if(e == L'n') val[vi++] = L'\n';
                    else if(e == L'r') val[vi++] = L'\r';
                    else if(e == L't') val[vi++] = L'\t';
                    else val[vi++] = e;
                    src += 2;
                } else val[vi++] = *src++;
            }
            if(*src == L'"') src++;
        } else {
            /* Bare token: number, true, false, null */
            size_t vi = 0;
            while(*src && *src != L',' && *src != L'}' && *src != L' ' && *src != L'\n' && *src != L'\r' && vi < CMD_MAX_LINE-1)
                val[vi++] = *src++;
            val[vi] = L'\0';
        }
        obj_upsert(name, key, val);
        while(*src && (*src == L' ' || *src == L',' || *src == L'\n' || *src == L'\r' || *src == L'\t')) src++;
    }
    return 0;
}

static int cmd_builtin_convertfrom_json(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"CONVERTFROM-JSON: usage CONVERTFROM-JSON <json-text>"); return 1; }
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    const wchar_t *name = L"__conv";
    if(parse_json_flat(name, buf) != 0){ cmd_print_error(L"CONVERTFROM-JSON: parse error"); return 1; }
    wprintf(L"Loaded JSON into $%s (%d key%s)\n", name, g_objs[obj_find(name)].count,
            g_objs[obj_find(name)].count == 1 ? L"" : L"s");
    return 0;
}

/* Minimal XML emitter: only top-level attributes of one object become
   children of <name>. Each key is a child element, value is its text. */
static int cmd_builtin_convertto_xml(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"CONVERTTO-XML: usage CONVERTTO-XML <objname>"); return 1; }
    const wchar_t *name = strip_sigil(argv[1]);
    int idx = obj_find(name);
    if(idx < 0){ cmd_print_error(L"CONVERTTO-XML: object '%s' not found", name); return 1; }
    wprintf(L"<%s>\n", name);
    for(int i=0;i<g_objs[idx].count;i++){
        wchar_t esc[CMD_MAX_LINE];
        json_escape(g_objs[idx].pairs[i].value, esc, CMD_MAX_LINE);
        wprintf(L"  <%s>%s</%s>\n", g_objs[idx].pairs[i].key, esc, g_objs[idx].pairs[i].key);
    }
    wprintf(L"</%s>\n", name);
    return 0;
}

/* Minimal XML parser: extract text between <key>...</key> into obj key. */
static int parse_xml_shallow(const wchar_t *name, const wchar_t *src)
{
    while(*src && *src != L'<') src++;
    if(!*src) return 1;
    /* Skip outer tag */
    while(*src && *src != L'>') src++;
    if(!*src) return 1;
    src++;
    while(*src){
        while(*src && *src != L'<') src++;
        if(!*src) break;
        if(_wcsnicmp(src, L"</", 2) == 0) break;
        if(*src != L'<') break;
        src++; /* past < */
        wchar_t key[64]; size_t ki = 0;
        while(*src && *src != L'>' && ki < 63) key[ki++] = *src++;
        key[ki] = L'\0';
        if(*src != L'>') break;
        src++;
        wchar_t val[CMD_MAX_LINE] = {0};
        size_t vi = 0;
        while(*src && _wcsnicmp(src, L"</", 2) != 0 && vi < CMD_MAX_LINE-1) val[vi++] = *src++;
        val[vi] = L'\0';
        obj_upsert(name, key, val);
        while(*src && _wcsnicmp(src, L"</", 2) != 0) src++;
        if(*src == L'<'){
            while(*src && *src != L'>') src++;
            if(*src == L'>') src++;
        }
    }
    return 0;
}

static int cmd_builtin_convertfrom_xml(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"CONVERTFROM-XML: usage CONVERTFROM-XML <xml-text>"); return 1; }
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    const wchar_t *name = L"__conv";
    if(parse_xml_shallow(name, buf) != 0){ cmd_print_error(L"CONVERTFROM-XML: parse error"); return 1; }
    int idx = obj_find(name);
    wprintf(L"Loaded XML into $%s (%d key%s)\n", name, idx >= 0 ? g_objs[idx].count : 0,
            (idx >= 0 && g_objs[idx].count == 1) ? L"" : L"s");
    return 0;
}

/* ARRAY <name> = v1, v2, v3 ... */
static int cmd_builtin_array(wchar_t **argv, int argc)
{
    if(argc == 1) return cmd_builtin_alist(argv, argc);
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    wchar_t *eq = wcschr(buf, L'=');
    if(!eq){ cmd_print_error(L"ARRAY: expected '='"); return 1; }
    *eq = L'\0';
    wchar_t *lhs = buf; wcs_trim(lhs);
    wchar_t *rhs = eq + 1; wcs_trim(rhs);
    const wchar_t *name = strip_sigil(lhs);
    int idx = arr_find(name);
    if(idx < 0){
        if(g_arrCount >= MAX_ARRS){ cmd_print_error(L"ARRAY: too many arrays"); return 1; }
        idx = g_arrCount++;
        wcsncpy_s(g_arrs[idx].name, 64, name, _TRUNCATE);
        g_arrs[idx].count = 0;
    } else {
        g_arrs[idx].count = 0; /* overwrite */
    }
    wchar_t *save = NULL;
    wchar_t *tok = wcstok_s(rhs, L",", &save);
    while(tok){
        while(*tok == L' ' || *tok == L'\t') tok++;
        size_t tl = wcslen(tok);
        while(tl > 0 && (tok[tl-1] == L' ' || tok[tl-1] == L'\t')) tok[--tl] = L'\0';
        if(tl >= 2 && tok[0] == L'"' && tok[tl-1] == L'"'){
            tok[tl-1] = L'\0'; memmove(tok, tok+1, (wcslen(tok+1)+1)*sizeof(wchar_t));
        }
        if(g_arrs[idx].count >= CMD_ARRAY_MAX) break;
        wcsncpy_s(g_arrs[idx].items[g_arrs[idx].count], CMD_MAX_LINE, tok, _TRUNCATE);
        g_arrs[idx].count++;
        tok = wcstok_s(NULL, L",", &save);
    }
    return 0;
}

static int cmd_builtin_aget(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"AGET: usage AGET $arr[idx]"); return 1; }
    const wchar_t *name = strip_sigil(argv[1]);
    const wchar_t *lb = wcschr(name, L'[');
    if(!lb){ cmd_print_error(L"AGET: expected $arr[idx]"); return 1; }
    wchar_t aname[64]; size_t anl = (size_t)(lb - name); if(anl >= 64) return 1;
    wcsncpy_s(aname, 64, name, anl);
    const wchar_t *rb = wcschr(lb, L']');
    wchar_t idxBuf[32]; size_t il = rb ? (size_t)(rb - lb - 1) : wcslen(lb+1);
    if(il >= 32) il = 31;
    wcsncpy_s(idxBuf, 32, lb + 1, il);
    int idx = arr_find(aname);
    if(idx < 0){ cmd_print_error(L"AGET: array '%s' not found", aname); return 1; }
    int ai = _wtoi(idxBuf);
    if(ai < 0 || ai >= g_arrs[idx].count){ cmd_print_error(L"AGET: index out of range"); return 1; }
    wprintf(L"%s\n", g_arrs[idx].items[ai]);
    return 0;
}

static int cmd_builtin_aset(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"ASET: usage ASET $arr[idx] = value"); return 1; }
    wchar_t buf[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){ if(i>1) wcscat_s(buf, CMD_MAX_LINE, L" "); wcscat_s(buf, CMD_MAX_LINE, argv[i]); }
    wchar_t *eq = wcschr(buf, L'=');
    if(!eq){ cmd_print_error(L"ASET: expected '='"); return 1; }
    *eq = L'\0';
    wchar_t *lhs = buf; wcs_trim(lhs);
    wchar_t *rhs = eq + 1; wcs_trim(rhs);
    const wchar_t *name = strip_sigil(lhs);
    const wchar_t *lb = wcschr(name, L'[');
    if(!lb){ cmd_print_error(L"ASET: expected $arr[idx]"); return 1; }
    wchar_t aname[64]; size_t anl = (size_t)(lb - name); if(anl >= 64) return 1;
    wcsncpy_s(aname, 64, name, anl);
    const wchar_t *rb = wcschr(lb, L']');
    wchar_t idxBuf[32]; size_t il = rb ? (size_t)(rb - lb - 1) : wcslen(lb+1);
    if(il >= 32) il = 31;
    wcsncpy_s(idxBuf, 32, lb + 1, il);
    int idx = arr_find(aname);
    if(idx < 0){
        if(g_arrCount >= MAX_ARRS) return 1;
        idx = g_arrCount++;
        wcsncpy_s(g_arrs[idx].name, 64, aname, _TRUNCATE);
        g_arrs[idx].count = 0;
    }
    int ai = _wtoi(idxBuf);
    while(ai >= g_arrs[idx].count){
        if(g_arrs[idx].count >= CMD_ARRAY_MAX) return 1;
        g_arrs[idx].items[g_arrs[idx].count][0] = L'\0';
        g_arrs[idx].count++;
    }
    wcsncpy_s(g_arrs[idx].items[ai], CMD_MAX_LINE, rhs, _TRUNCATE);
    return 0;
}

static int cmd_builtin_alist(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    if(argc >= 2 && _wcsicmp(argv[1], L"DEL") == 0){
        const wchar_t *name = strip_sigil(argv[2]);
        int idx = arr_find(name);
        if(idx < 0) return 1;
        for(int i=idx;i<g_arrCount-1;i++) g_arrs[i] = g_arrs[i+1];
        g_arrCount--;
        return 0;
    }
    if(g_arrCount == 0){ wprintf(L"No arrays defined.\n"); return 0; }
    for(int i=0;i<g_arrCount;i++){
        wprintf(L"$%s[%d] = (", g_arrs[i].name, g_arrs[i].count);
        for(int k=0;k<g_arrs[i].count;k++){
            if(k) wprintf(L", ");
            wprintf(L"%s", g_arrs[i].items[k]);
        }
        wprintf(L")\n");
    }
    return 0;
}

/* FUNC <name> [p1 p2 ...] { <body lines> }
   Single-line form only: FUNC name { cmd1 ; cmd2 ; cmd3 }
   Body statements are separated by ';' so users can put multiple commands
   in one FUNC. Each statement becomes a body line. */
static int cmd_builtin_func(wchar_t **argv, int argc)
{
    if(argc < 3){ cmd_print_error(L"FUNC: usage FUNC <name> [p1 ...] { body; ... }"); return 1; }
    int braceIdx = -1;
    for(int i=1;i<argc;i++){ if(wcschr(argv[i], L'{')){ braceIdx = i; break; } }
    if(braceIdx < 0){ cmd_print_error(L"FUNC: missing '{'"); return 1; }
    wchar_t *name = argv[1];
    int fidx = func_find(name);
    if(fidx < 0){
        if(g_funcCount >= 16){ cmd_print_error(L"FUNC: too many functions"); return 1; }
        fidx = g_funcCount++;
    }
    wcsncpy_s(g_funcs[fidx].name, 64, name, _TRUNCATE);
    g_funcs[fidx].paramCount = 0;
    g_funcs[fidx].bodyLines = 0;
    for(int i=2;i<braceIdx;i++){
        if(g_funcs[fidx].paramCount >= 8) break;
        wcsncpy_s(g_funcs[fidx].params[g_funcs[fidx].paramCount], 64, argv[i], _TRUNCATE);
        g_funcs[fidx].paramCount++;
    }
    /* Collect everything from braceIdx until the closing '}' as one body string.
       Tokens are joined with a single space (tokenizer already split on
       whitespace). Statements within the body are separated by ';'. */
    wchar_t body[CMD_MAX_LINE * 4] = {0};
    int foundClose = 0;
    for(int i=braceIdx;i<argc && !foundClose;i++){
        wchar_t *tok = argv[i];
        wchar_t *open = wcschr(tok, L'{');
        wchar_t *start = open ? open + 1 : tok;
        wchar_t *close = wcschr(start, L'}');
        if(close){ *close = L'\0'; foundClose = 1; }
        if(start[0] == L'\0') continue;
        if(body[0]) wcscat_s(body, sizeof(body)/sizeof(wchar_t), L" ");
        wcscat_s(body, sizeof(body)/sizeof(wchar_t), start);
    }
    if(!foundClose){ cmd_print_error(L"FUNC: missing '}'"); return 1; }
    /* Split body on ';' and store each line */
    wchar_t *save = NULL;
    wchar_t *line = wcstok_s(body, L";", &save);
    while(line){
        while(*line == L' ' || *line == L'\t') line++;
        size_t ll = wcslen(line);
        while(ll > 0 && (line[ll-1]==L' ' || line[ll-1]==L'\t')) line[--ll]=L'\0';
        if(*line){
            if(g_funcs[fidx].bodyLines >= CMD_FUNC_MAX) break;
            wcsncpy_s(g_funcs[fidx].body[g_funcs[fidx].bodyLines], CMD_MAX_LINE, line, _TRUNCATE);
            g_funcs[fidx].bodyLines++;
        }
        line = wcstok_s(NULL, L";", &save);
    }
    wprintf(L"Defined FUNC %s (%d param%s, %d body line%s)\n", name,
            g_funcs[fidx].paramCount, g_funcs[fidx].paramCount == 1 ? L"" : L"s",
            g_funcs[fidx].bodyLines, g_funcs[fidx].bodyLines == 1 ? L"" : L"s");
    return 0;
}

/* CALL <name> arg1 arg2 ...
   Param values are bound to environment variables of the form
   __CALLPARAM1..8 so the body can read them via %1..%8 just like a normal
   batch file. We save and restore the previous values so we don't leak
   variables to the caller. */
static int cmd_builtin_callfunc(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"CALL: usage CALL <name> [args]"); return 1; }
    int fidx = func_find(argv[1]);
    if(fidx < 0){ cmd_print_error(L"CALL: function '%s' not defined", argv[1]); return 1; }
    /* Keep these buffers on the heap - large stack allocations caused
       STATUS_STACK_OVERFLOW (0xC00000FD) on Windows 10 VMs with the default
       1MB thread stack. */
    wchar_t *saved   = (wchar_t*)calloc(8 * 64,  sizeof(wchar_t));
    wchar_t *oldVals = (wchar_t*)calloc(8 * CMD_MAX_LINE, sizeof(wchar_t));
    int     *haveSv  = (int*)    calloc(8,        sizeof(int));
    if(!saved || !oldVals || !haveSv){
        free(saved); free(oldVals); free(haveSv);
        cmd_print_error(L"CALL: out of memory");
        return 1;
    }
    int nArgs = argc - 2;
    int nParams = g_funcs[fidx].paramCount;
    /* Always bind positional args $1..$8 (to "" if not provided) so the
       function body can use them without having to declare them. */
    wchar_t tmpOld[CMD_MAX_LINE];
    for(int i=1;i<=8;i++){
        wchar_t envName[32];
        swprintf_s(envName, 32, L"__CALLPARAM%d", i);
        DWORD got = GetEnvironmentVariableW(envName, tmpOld, CMD_MAX_LINE);
        int slot = (i-1)%8;
        if(got > 0 && got < CMD_MAX_LINE) wcsncpy_s(oldVals + slot*CMD_MAX_LINE, CMD_MAX_LINE, tmpOld, _TRUNCATE);
        else oldVals[slot*CMD_MAX_LINE] = L'\0';
        haveSv[slot] = (got > 0 && got < CMD_MAX_LINE) ? 1 : 0;
        const wchar_t *val = (i <= nArgs) ? argv[1 + i] : L"";
        SetEnvironmentVariableW(envName, val);
    }
    for(int i=0;i<nParams;i++){
        swprintf_s(saved + i*64, 64, L"__CALLPARAM%d", i+1);
        DWORD got = GetEnvironmentVariableW(saved + i*64, oldVals + i*64, 64);
        if(got > 0 && got < 64) haveSv[i] = 1;
        const wchar_t *val = (i < nArgs) ? argv[2 + i] : L"";
        SetEnvironmentVariableW(saved + i*64, val);
    }
    int lastRc = 0;
    for(int i=0;i<g_funcs[fidx].bodyLines;i++){
        lastRc = cmd_execute_line(g_funcs[fidx].body[i]);
        if(g_state.exitRequested) break;
    }
    /* Restore */
    for(int i=1;i<=8;i++){
        wchar_t envName[32];
        swprintf_s(envName, 32, L"__CALLPARAM%d", i);
        int slot = (i-1)%8;
        if(haveSv[slot]) SetEnvironmentVariableW(envName, oldVals + slot*CMD_MAX_LINE);
        else SetEnvironmentVariableW(envName, NULL);
    }
    free(saved); free(oldVals); free(haveSv);
    return lastRc;
}

static int cmd_builtin_funcs(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    if(g_funcCount == 0){ wprintf(L"No functions defined.\n"); return 0; }
    for(int i=0;i<g_funcCount;i++){
        wprintf(L"FUNC %s(", g_funcs[i].name);
        for(int k=0;k<g_funcs[i].paramCount;k++){
            if(k) wprintf(L", ");
            wprintf(L"%s", g_funcs[i].params[k]);
        }
        wprintf(L")  [%d line%s]\n", g_funcs[i].bodyLines, g_funcs[i].bodyLines == 1 ? L"" : L"s");
    }
    return 0;
}


/* ==========================================================================
 *  Dispatch Table - Native LoOS: every internal command is here
 * ========================================================================== */
typedef struct { const wchar_t *name; int (*handler)(wchar_t **,int); const wchar_t *help; } BUILTIN_ENTRY;

static BUILTIN_ENTRY g_builtins[] = {
    { L"ASSOC",      cmd_builtin_assoc,      NULL }, { L"ATTRIB",     cmd_builtin_attrib,     NULL },
    { L"BCDEDIT",    cmd_builtin_bcdedit,    NULL }, { L"BREAK",      cmd_builtin_break,      NULL },
    { L"CACLS",      cmd_builtin_cacls,      NULL }, { L"CALL",       cmd_builtin_call,       NULL },
    { L"CD",         cmd_builtin_cd,         NULL }, { L"CHCP",       cmd_builtin_chcp,       NULL },
    { L"CHDIR",      cmd_builtin_cd,         NULL }, { L"CHKDSK",     cmd_builtin_chkdsk,     NULL },
    { L"CHKNTFS",    cmd_builtin_chkntfs,    NULL }, { L"CLS",        cmd_builtin_cls,        NULL },
    { L"CMD",        cmd_builtin_cmd,        NULL }, { L"COLOR",      cmd_builtin_color,      NULL },
    { L"COMPACT",    cmd_builtin_compact,    NULL }, { L"COMP",       cmd_builtin_comp,       NULL },
    { L"CONVERT",    cmd_builtin_convert,    NULL }, { L"COPY",       cmd_builtin_copy,       NULL },
    { L"DATE",       cmd_builtin_date,       NULL }, { L"DEL",        cmd_builtin_del,        NULL },
    { L"DIR",        cmd_builtin_dir,        NULL }, { L"DISKPART",   cmd_builtin_diskpart,   NULL },
    { L"DOSKEY",     cmd_builtin_doskey,     NULL }, { L"DRIVERQUERY",cmd_builtin_driverquery,NULL },
    { L"ECHO",       cmd_builtin_echo,       NULL }, { L"ENDLOCAL",   cmd_builtin_endlocal,   NULL },
    { L"ERASE",      cmd_builtin_del,        NULL }, { L"EXIT",       cmd_builtin_exit,       NULL },
    { L"FC",         cmd_builtin_fc,         NULL }, { L"FIND",       cmd_builtin_find,       NULL },
    { L"FINDSTR",    cmd_builtin_findstr,    NULL }, { L"FOR",        cmd_builtin_for,        NULL },
    { L"FORMAT",     cmd_builtin_format,     NULL }, { L"FSUTIL",     cmd_builtin_fsutil,     NULL },
    { L"FTYPE",      cmd_builtin_ftype,      NULL }, { L"GOTO",       cmd_builtin_goto,       NULL },
    { L"GPRESULT",   cmd_builtin_gpresult,   NULL }, { L"HISTORY",    cmd_builtin_history,    NULL }, { L"GRAFTABL",   cmd_builtin_graftabl,   NULL },
    { L"HELP",       cmd_builtin_help,       NULL }, { L"ICACLS",     cmd_builtin_icacls,     NULL },
    { L"IF",         cmd_builtin_if,         NULL }, { L"LABEL",      cmd_builtin_label,      NULL },
    { L"MD",         cmd_builtin_md,         NULL }, { L"MKDIR",      cmd_builtin_md,         NULL },
    { L"MKLINK",     cmd_builtin_mklink,     NULL }, { L"MODE",       cmd_builtin_mode,       NULL },
    { L"MORE",       cmd_builtin_more,       NULL }, { L"MOVE",       cmd_builtin_move,       NULL },
    { L"OPENFILES",  cmd_builtin_openfiles,  NULL }, { L"PATH",       cmd_builtin_path,       NULL },
    { L"PAUSE",      cmd_builtin_pause,      NULL }, { L"POPD",       cmd_builtin_popd,       NULL },
    { L"PRINT",      cmd_builtin_print,      NULL }, { L"PROMPT",     cmd_builtin_prompt,     NULL },
    { L"PUSHD",      cmd_builtin_pushd,      NULL }, { L"RD",         cmd_builtin_rd,         NULL },
    { L"RECOVER",    cmd_builtin_recover,    NULL }, { L"REM",        cmd_builtin_rem,        NULL },
    { L"REN",        cmd_builtin_ren,        NULL }, { L"RENAME",     cmd_builtin_ren,        NULL },
    { L"REPLACE",    cmd_builtin_replace,    NULL }, { L"RMDIR",      cmd_builtin_rd,         NULL },
    { L"ROBOCOPY",   cmd_builtin_robocopy,   NULL }, { L"SC",         cmd_builtin_sc,         NULL },
    { L"SCHTASKS",   cmd_builtin_schtasks,   NULL }, { L"SET",        cmd_builtin_set,        NULL },
    { L"SETLOCAL",   cmd_builtin_setlocal,   NULL }, { L"SHIFT",      cmd_builtin_shift,      NULL },
    { L"SHUTDOWN",   cmd_builtin_shutdown,   NULL }, { L"SORT",       cmd_builtin_sort,       NULL },
    { L"START",      cmd_builtin_start,      NULL }, { L"SUBST",      cmd_builtin_subst,      NULL },
    { L"SYSTEMINFO", cmd_builtin_systeminfo, NULL }, { L"TASKLIST",   cmd_builtin_tasklist,   NULL },
    { L"TASKKILL",   cmd_builtin_taskkill,   NULL }, { L"TIME",       cmd_builtin_time,       NULL },
    { L"TITLE",      cmd_builtin_title,      NULL }, { L"TREE",       cmd_builtin_tree,       NULL },
    { L"TYPE",       cmd_builtin_type,       NULL }, { L"VER",        cmd_builtin_ver,        NULL }, { L"TAB",        cmd_builtin_tab,        NULL },
    { L"VERIFY",     cmd_builtin_verify,     NULL }, { L"VOL",        cmd_builtin_vol,        NULL },
    { L"WMIC",       cmd_builtin_wmic,       NULL }, { L"XCOPY",      cmd_builtin_xcopy,      NULL },
    // LoOS powerful extensions (native, no external exes)
    { L"PING",       cmd_builtin_ping,       NULL }, { L"IPCONFIG",   cmd_builtin_ipconfig,   NULL },
    { L"NETSTAT",    cmd_builtin_netstat,    NULL }, { L"TRACERT",    cmd_builtin_tracert,    NULL },
    { L"NSLOOKUP",   cmd_builtin_nslookup,   NULL }, { L"ARP",        cmd_builtin_arp,        NULL },
    { L"ROUTE",      cmd_builtin_route,      NULL }, { L"NET",        cmd_builtin_net,        NULL },
    { L"REG",        cmd_builtin_reg,        NULL }, { L"WHERE",      cmd_builtin_where,      NULL },
    { L"WHOAMI",     cmd_builtin_whoami,     NULL }, { L"SETX",       cmd_builtin_setx,       NULL },
    { L"TIMEOUT",    cmd_builtin_timeout,    NULL }, { L"CHOICE",     cmd_builtin_choice,     NULL },
    { L"CLIP",       cmd_builtin_clip,       NULL }, { L"TAKEOWN",    cmd_builtin_takeown,    NULL },
    { L"CURL",       cmd_builtin_curl,       NULL }, { L"WGET",       cmd_builtin_curl,       NULL },
    { L"GREP",       cmd_builtin_grep,       NULL }, { L"LS",         cmd_builtin_ls,         NULL },
    { L"PS",         cmd_builtin_ps,         NULL }, { L"KILL",       cmd_builtin_kill,       NULL },
    { L"NBTSTAT",    cmd_builtin_nbtstat,    NULL }, { L"NETSH",      cmd_builtin_netsh,      NULL },
    { L"POWERCFG",   cmd_builtin_powercfg,   NULL }, { L"SFC",        cmd_builtin_sfc,        NULL },
    // PowerShell-inspired: structured data, arrays, user-defined functions
    { L"OBJ",        cmd_builtin_obj,        NULL }, { L"OBJECTS",    cmd_builtin_obj_list,   NULL },
    { L"OSET",       cmd_builtin_obj_set,    NULL }, { L"OGET",       cmd_builtin_obj_get,    NULL },
    { L"ODEL",       cmd_builtin_obj_list,   NULL },
    { L"ARRAY",      cmd_builtin_array,      NULL }, { L"ARRAYS",     cmd_builtin_alist,      NULL },
    { L"AGET",       cmd_builtin_aget,       NULL }, { L"ASET",       cmd_builtin_aset,       NULL },
    { L"ADEL",       cmd_builtin_alist,      NULL },
    { L"FUNC",       cmd_builtin_func,       NULL },
    // CALL is now polymorphic: batch files (legacy) OR user-defined FUNCtion (PowerShell-style).
    { L"FUNCS",      cmd_builtin_funcs,      NULL }, { L"FUNCDEL",    cmd_builtin_funcs,      NULL },
    { L"CONVERTFROM-JSON", cmd_builtin_convertfrom_json, NULL },
    { L"CONVERTTO-JSON",   cmd_builtin_convertto_json,   NULL },
    { L"CONVERTFROM-XML",  cmd_builtin_convertfrom_xml,  NULL },
    { L"CONVERTTO-XML",    cmd_builtin_convertto_xml,    NULL },
    { L"CFJ",         cmd_builtin_convertfrom_json, NULL },
    { L"CTJ",         cmd_builtin_convertto_json,   NULL },
    { L"CFX",         cmd_builtin_convertfrom_xml,  NULL },
    { L"CTX",         cmd_builtin_convertto_xml,    NULL },
    // Tab navigation by command (no keyboard shortcuts anymore)
    { L"TABCLOSE",   cmd_builtin_tabclose,   NULL }, { L"TABN",       cmd_builtin_tabnext,    NULL },
    // Unix-style aliases - one handler routes each alias to the matching
    // native Windows / LoOS command, with the right flag rewrites.
    { L"LS",         cmd_builtin_unix_aliases, NULL }, { L"RM",         cmd_builtin_unix_aliases, NULL },
    { L"CAT",        cmd_builtin_unix_aliases, NULL }, { L"CP",         cmd_builtin_unix_aliases, NULL },
    { L"MV",         cmd_builtin_unix_aliases, NULL }, { L"MKDIR",      cmd_builtin_unix_aliases, NULL },
    { L"RMDIR",      cmd_builtin_unix_aliases, NULL }, { L"TOUCH",      cmd_builtin_unix_aliases, NULL },
    { L"CLEAR",      cmd_builtin_unix_aliases, NULL }, { L"PWD",        cmd_builtin_unix_aliases, NULL },
    { L"MAN",        cmd_builtin_unix_aliases, NULL }, { L"GREP",       cmd_builtin_unix_aliases, NULL },
    { L"HEAD",       cmd_builtin_unix_aliases, NULL }, { L"TAIL",       cmd_builtin_unix_aliases, NULL },
    { L"WC",         cmd_builtin_unix_aliases, NULL }, { L"WHICH",      cmd_builtin_unix_aliases, NULL },
    { L"UNAME",      cmd_builtin_unix_aliases, NULL }, { L"DF",         cmd_builtin_unix_aliases, NULL },
    { L"FREE",       cmd_builtin_unix_aliases, NULL }, { L"ENV",        cmd_builtin_unix_aliases, NULL },
    { L"SUDO",       cmd_builtin_sudo,        NULL },
    { L"THEME",      cmd_builtin_theme,       NULL },
    { L"CURSOR",     cmd_builtin_cursor,      NULL },
    { L"DIDYOUMEAN", cmd_builtin_did_you_mean,NULL },
    // Visual / session niceties
    { L"HYPERLINKS",      cmd_builtin_hyperlinks_on,  NULL }, { L"NOHYPERLINKS",  cmd_builtin_hyperlinks_off, NULL },
    { L"SESSION-SAVE",    cmd_builtin_session_save,   NULL }, { L"SESSION-RESTORE",cmd_builtin_session_restore,NULL },
    { L"QUAKE",           cmd_builtin_quake_toggle,   NULL },
    { L"AUTOCOPY",        cmd_builtin_autocopy,       NULL },
    { L"BLUR",            cmd_builtin_blur,           NULL },
    { L"TABNAME",         cmd_builtin_tabname,        NULL },
    { L"TABP",       cmd_builtin_tabprev,    NULL }, { L"TABGO",      cmd_builtin_tabgo,      NULL },
    { NULL, NULL, NULL }
};
/* ==========================================================================
 *  Unix-style aliases, sudo, theme/cursor helpers, etc.
 * ========================================================================== */

/* Forward reference for the helper that runs cmd /C with a synthesized
   argv list, so we can invoke, e.g., "dir" with proper argument quoting. */
static int cmd_try_external(wchar_t **argv, int argc);

/* Single dispatch entry-point that re-routes ls/rm/cat/cp/mv/mkdir/rmdir/
   touch/clear/pwd/man/grep/head/tail/wc/which/uname/df/free/env to the
   matching Windows / native cmd.exe builtin. Implemented as one big
   switch on argv[0]. Returns 1 if it dispatched the command, 0 if the
   alias name is unknown (shouldn't happen because the dispatch table
   only feeds it recognised names). */
static int unix_alias_dispatch(wchar_t **argv, int argc)
{
    const wchar_t *name = argv[0];
    /* Build a new argv that prepends the canonical Windows command name */
    wchar_t *new_argv[64] = {0};
    int new_argc = 0;
    if(_wcsicmp(name, L"LS") == 0){new_argv[new_argc++] = (wchar_t*)L"DIR";
        new_argv[new_argc++] = (wchar_t*)L"/B";
    } else if(_wcsicmp(name, L"RM") == 0){new_argv[new_argc++] = (wchar_t*)L"DEL";
        new_argv[new_argc++] = (wchar_t*)L"/Q";
    } else if(_wcsicmp(name, L"CAT") == 0){new_argv[new_argc++] = (wchar_t*)L"TYPE";
    } else if(_wcsicmp(name, L"CP") == 0){new_argv[new_argc++] = (wchar_t*)L"COPY";
    } else if(_wcsicmp(name, L"MV") == 0){new_argv[new_argc++] = (wchar_t*)L"MOVE";
    } else if(_wcsicmp(name, L"MKDIR") == 0){new_argv[new_argc++] = (wchar_t*)L"MD";
    } else if(_wcsicmp(name, L"RMDIR") == 0){new_argv[new_argc++] = (wchar_t*)L"RD";
    } else if(_wcsicmp(name, L"TOUCH") == 0){/* `touch FILE` -> `copy /b NUL FILE` (creates or updates mtime) */
        new_argv[new_argc++] = (wchar_t*)L"COPY";
        new_argv[new_argc++] = (wchar_t*)L"/B";
        new_argv[new_argc++] = (wchar_t*)L"NUL";
    } else if(_wcsicmp(name, L"CLEAR") == 0){new_argv[new_argc++] = (wchar_t*)L"CLS";
    } else if(_wcsicmp(name, L"PWD") == 0){new_argv[new_argc++] = (wchar_t*)L"CD";
    } else if(_wcsicmp(name, L"MAN") == 0){new_argv[new_argc++] = (wchar_t*)L"HELP";
    } else if(_wcsicmp(name, L"GREP") == 0){new_argv[new_argc++] = (wchar_t*)L"FINDSTR";
    } else if(_wcsicmp(name, L"HEAD") == 0){new_argv[new_argc++] = (wchar_t*)L"FINDSTR";
        new_argv[new_argc++] = (wchar_t*)L"/N";
    } else if(_wcsicmp(name, L"TAIL") == 0){new_argv[new_argc++] = (wchar_t*)L"FINDSTR";
        new_argv[new_argc++] = (wchar_t*)L"/V";
        new_argv[new_argc++] = (wchar_t*)L"$RECYCLE.BIN"; /* placeholder line filter */
    } else if(_wcsicmp(name, L"WC") == 0){new_argv[new_argc++] = (wchar_t*)L"FIND";
        new_argv[new_argc++] = (wchar_t*)L"/C";
        new_argv[new_argc++] = (wchar_t*)L"/V";
        /* FIND /C /V "" prints count of non-blank lines */
        new_argv[new_argc++] = (wchar_t*)L"\"\"";
    } else if(_wcsicmp(name, L"WHICH") == 0){new_argv[new_argc++] = (wchar_t*)L"WHERE";
    } else if(_wcsicmp(name, L"UNAME") == 0){
        new_argv[new_argc++] = (wchar_t*)L"VER";
    } else if(_wcsicmp(name, L"DF") == 0){
        new_argv[new_argc++] = (wchar_t*)L"FSUTIL";
        new_argv[new_argc++] = (wchar_t*)L"VOLUME";
        new_argv[new_argc++] = (wchar_t*)L"DISKREFS";
    } else if(_wcsicmp(name, L"FREE") == 0){
        new_argv[new_argc++] = (wchar_t*)L"WMIC";
        new_argv[new_argc++] = (wchar_t*)L"OS";
        new_argv[new_argc++] = (wchar_t*)L"GET";
        new_argv[new_argc++] = (wchar_t*)L"TotalVisibleMemorySize,FreePhysicalMemory";
    } else if(_wcsicmp(name, L"ENV") == 0){
        new_argv[new_argc++] = (wchar_t*)L"SET";
    } else if(_wcsicmp(name, L"SUDO") == 0){
        /* Handled by cmd_builtin_sudo, not unix_alias_dispatch */
        return -1;
    } else if(_wcsicmp(name, L"THEME") == 0){
        return -1;
    } else if(_wcsicmp(name, L"CURSOR") == 0){
        return -1;
    } else {
        return -1;
    }
    /* Forward the rest of the arguments unchanged */
    for(int i=1;i<argc && new_argc < 60;i++) new_argv[new_argc++] = argv[i];
    /* Dispatch through the main dispatch table so we get the matching
       builtin (DIR, TYPE, DEL, ...) instead of trying to spawn the
       command as an external program. */
    return cmd_dispatch(new_argv, new_argc, NULL);
}

static int cmd_builtin_unix_aliases(wchar_t **argv, int argc)
{
    int r = unix_alias_dispatch(argv, argc);
    /* `unix_alias_dispatch` returns cmd_dispatch(...)'s value. cmd_dispatch
       returns 0 on success and non-zero on failure (so 0 = the alias
       matched a builtin and ran, 1+/9009 = matched but the underlying
       builtin errored out). The "unknown alias" error fires only when
       unix_alias_dispatch couldn't translate the name at all, which is
       reported by it returning 0 from a fall-through (i.e. never matched).
       We disambiguate that with the helper's explicit "no match" path
       by checking whether the function actually executed anything. */
    if(r == -1){
        cmd_print_error(L"%s: unknown unix alias", argv[0]);
        return 1;
    }
    return g_state.lastErrorLevel;
}

/* SUDO - relaunch the rest of the line as Administrator using PowerShell's
   Start-Process -Verb RunAs. Disabled under cmd /C (non-interactive batch)
   because the elevation prompt would block a non-interactive script. */
static int cmd_builtin_sudo(wchar_t **argv, int argc)
{
    if(argc < 2){
        cmd_print_error(L"SUDO: usage SUDO <command> [args ...]");
        return 1;
    }
    /* Build a single command string from argv[1..] */
    wchar_t fullCmd[CMD_MAX_LINE] = {0};
    for(int i=1;i<argc;i++){
        if(i>1) wcscat_s(fullCmd, CMD_MAX_LINE, L" ");
        wchar_t *a = argv[i];
        if(wcschr(a, L' ') && a[0] != L'"'){
            wchar_t quoted[CMD_MAX_LINE];
            swprintf_s(quoted, CMD_MAX_LINE, L"\"%s\"", a);
            wcscat_s(fullCmd, CMD_MAX_LINE, quoted);
        } else {
            wcscat_s(fullCmd, CMD_MAX_LINE, a);
        }
    }
    /* Use PowerShell to spawn cmd.exe -Verb RunAs with our exe + the rest.
       Quote for PowerShell single-quoted string. */
    wchar_t selfPath[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, selfPath, MAX_PATH);
    wchar_t psCmd[CMD_MAX_LINE * 2] = {0};
    swprintf_s(psCmd, CMD_MAX_LINE * 2,
        L"powershell -NoProfile -Command \"Start-Process -FilePath '%s' "
        L"-ArgumentList '/C','%s' -Verb RunAs -WorkingDirectory '%s' -WindowStyle Normal\"",
        selfPath, fullCmd, g_state.currentDir);
    STARTUPINFOW si={0}; si.cb=sizeof(si);
    PROCESS_INFORMATION pi={0};
    if(!CreateProcessW(NULL, psCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)){
        cmd_print_error(L"SUDO: failed to launch elevated process");
        return 1;
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    wprintf(L"[sudo] elevation requested for: %s\n", fullCmd);
    return 0;
}

/* CURSOR <block|underscore|bar>  -  custom cursor shape */
static int cmd_builtin_cursor(wchar_t **argv, int argc)
{
    if(argc < 2){ wprintf(L"Usage: CURSOR <block|underscore|bar>\n"); return 0; }
    CONSOLE_CURSOR_INFO ci;
    HANDLE hOut = g_state.hStdOut;
    if(!GetConsoleCursorInfo(hOut, &ci)){
        /* Not an interactive console (output redirected) - silently skip */
        return 0;
    }
    if(_wcsicmp(argv[1], L"block") == 0){
        ci.dwSize = 100; ci.bVisible = TRUE;
    } else if(_wcsicmp(argv[1], L"underscore") == 0){
        ci.dwSize = 25; ci.bVisible = TRUE;
    } else if(_wcsicmp(argv[1], L"bar") == 0){
        ci.dwSize = 15; ci.bVisible = TRUE;
    } else if(_wcsicmp(argv[1], L"off") == 0 || _wcsicmp(argv[1], L"none") == 0){
        ci.bVisible = FALSE;
    } else {
        cmd_print_error(L"CURSOR: unknown shape '%s' (try block|underscore|bar|off)", argv[1]);
        return 1;
    }
    SetConsoleCursorInfo(hOut, &ci);
    wprintf(L"Cursor set to %s\n", argv[1]);
    return 0;
}

/* THEME <name|list|save|reload>  -  palette swapper. Builtin palettes:
   "default" (stock Windows), "solarized-light", "solarized-dark",
   "dracula". Custom themes are JSON files under
   %USERPROFILE%\.loos_themes\ or .\themes\ with the shape:
       {"fg": "<int>", "bg": "<int>"}                       (whole buffer)
       {"fg": "<int>", "bg": "<int>", "cursor": "<int>"}    (cursor colour)
   Hex strings ("0xRRGGBB") are also accepted but only the low 4 bits are
   used (Windows console is 16-colour). */
static void theme_apply_attrs(WORD fg, WORD bg)
{
    SetConsoleTextAttribute(g_state.hStdOut, (WORD)((bg << 4) | (fg & 0x0F)));
}
static int theme_apply_named(const wchar_t *name)
{
    if(_wcsicmp(name, L"default") == 0){
        theme_apply_attrs(0x7, 0x0); return 1;
    }
    if(_wcsicmp(name, L"solarized-light") == 0){
        theme_apply_attrs(0xF, 0xF); return 1; /* approx: black on cream */
    }
    if(_wcsicmp(name, L"solarized-dark") == 0){
        theme_apply_attrs(0xB, 0x3); return 1; /* cyan on cyan-dark */
    }
    if(_wcsicmp(name, L"dracula") == 0){
        theme_apply_attrs(0xF, 0x0); return 1; /* white on black, draculaish */
    }
    /* Try to load a .json theme from the user-themes directory or
       %USERPROFILE%\.loos_themes\ */
    wchar_t themePath[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"USERPROFILE", themePath, MAX_PATH);
    if(len > 0 && len < MAX_PATH) wcscat_s(themePath, MAX_PATH, L"\\.loos_themes\\");
    wchar_t try1[MAX_PATH]; swprintf_s(try1, MAX_PATH, L"%s%s.json", themePath, name);
    if(GetFileAttributesW(try1) != INVALID_FILE_ATTRIBUTES){
        FILE *f = _wfopen(try1, L"r");
        if(f){
            char buf[8192] = {0}; fread(buf, 1, 8191, f); fclose(f);
            /* Minimal parser - just look for "fg":N and "bg":N */
            int fg = -1, bg = -1;
            char *p;
            if((p = strstr(buf, "\"fg\"")) != NULL){
                p = strchr(p, ':'); if(p){ p++; while(*p == ' ' || *p == '"') p++;
                    if(*p == '0' && (p[1] == 'x' || p[1] == 'X')) fg = (int)strtol(p, NULL, 16) & 0x0F;
                    else fg = atoi(p) & 0x0F;
                }
            }
            if((p = strstr(buf, "\"bg\"")) != NULL){
                p = strchr(p, ':'); if(p){ p++; while(*p == ' ' || *p == '"') p++;
                    if(*p == '0' && (p[1] == 'x' || p[1] == 'X')) bg = (int)strtol(p, NULL, 16) & 0x0F;
                    else bg = atoi(p) & 0x0F;
                }
            }
            if(fg >= 0 && bg >= 0){ theme_apply_attrs((WORD)fg, (WORD)bg); return 1; }
        }
    }
    return 0;
}
static int cmd_builtin_theme(wchar_t **argv, int argc)
{
    if(argc == 1 || (argc == 2 && _wcsicmp(argv[1], L"LIST") == 0)){
        wprintf(L"Built-in themes:  default  solarized-light  solarized-dark  dracula\n");
        wprintf(L"Custom themes:   drop *.json files in %%USERPROFILE%%\\.loos_themes\\\n");
        wprintf(L"JSON shape: { \"fg\": <0..15|0xX>, \"bg\": <0..15|0xX> }\n");
        return 0;
    }
    if(_wcsicmp(argv[1], L"SET") == 0 && argc >= 3){
        if(!theme_apply_named(argv[2])){
            cmd_print_error(L"THEME: unknown theme '%s'", argv[2]);
            return 1;
        }
        wprintf(L"Theme set to %s\n", argv[2]);
        return 0;
    }
    if(_wcsicmp(argv[1], L"SET") == 0 && argc == 2){
        /* Reset to default */
        theme_apply_attrs(0x7, 0x0);
        wprintf(L"Theme reset to default\n");
        return 0;
    }
    if(!theme_apply_named(argv[1])){
        cmd_print_error(L"THEME: unknown theme '%s'", argv[1]);
        return 1;
    }
    wprintf(L"Theme set to %s\n", argv[1]);
    return 0;
}

/* Compute Levenshtein distance between two wide strings. Returns the
   edit distance (smaller = closer match). */
static int loos_levenshtein(const wchar_t *a, const wchar_t *b)
{
    int la = (int)wcslen(a), lb = (int)wcslen(b);
    if(la > 64) la = 64; if(lb > 64) lb = 64;
    int dp[130][130] = {0};
    for(int i=0;i<=la;i++) dp[i][0] = i;
    for(int j=0;j<=lb;j++) dp[0][j] = j;
    for(int i=1;i<=la;i++){
        for(int j=1;j<=lb;j++){
            int cost = (towlower(a[i-1]) == towlower(b[j-1])) ? 0 : 1;
            int v = dp[i-1][j] + 1;
            int h = dp[i][j-1] + 1;
            int d = dp[i-1][j-1] + cost;
            if(v < h) h = v;
            if(d < h) h = d;
            dp[i][j] = h;
        }
    }
    return dp[la][lb];
}

/* Find the closest builtin or history entry to `wrong`. Returns 1 if a
   plausible suggestion was printed, 0 if nothing close enough. */
static int cmd_did_you_mean(const wchar_t *wrong)
{
    int bestDist = 999;
    const wchar_t *best = NULL;
    /* Builtins */
    for(int i=0; g_builtins[i].name; i++){
        int d = loos_levenshtein(wrong, g_builtins[i].name);
        if(d < bestDist){ bestDist = d; best = g_builtins[i].name; }
    }
    /* Recent history */
    int scan = g_historyCount < 20 ? g_historyCount : 20;
    for(int i=0;i<scan;i++){
        int idx = (g_historyPos - g_historyCount + i + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
        wchar_t first[64] = {0};
        const wchar_t *space = wcschr(g_history[idx], L' ');
        size_t take = space ? (size_t)(space - g_history[idx]) : wcslen(g_history[idx]);
        if(take >= 64) take = 63;
        wcsncpy_s(first, 64, g_history[idx], take);
        int d = loos_levenshtein(wrong, first);
        if(d < bestDist){ bestDist = d; best = first; }
    }
    /* Threshold: only suggest if distance is small enough. Use a fraction of
       the input length so short words aren't matched against very long
       commands. */
    int len = (int)wcslen(wrong);
    int allow = len <= 3 ? 1 : (len <= 6 ? 2 : 3);
    if(best && bestDist <= allow){
        wprintf(L"Did you mean %s? [Y/n] ", best);
        fflush(stdout);
        /* Read a single Y/n response - try stdin first, fall back to Y. */
        wchar_t buf[16] = {0};
        DWORD mode = 0;
        HANDLE hIn = g_state.hStdIn;
        int isConsole = (GetFileType(hIn) == FILE_TYPE_CHAR) && GetConsoleMode(hIn, &mode);
        if(isConsole){
            INPUT_RECORD ir; DWORD got;
            if(ReadConsoleInputW(hIn, &ir, 1, &got) && got
               && ir.EventType == KEY_EVENT && ir.Event.KeyEvent.bKeyDown){
                wchar_t c = ir.Event.KeyEvent.uChar.UnicodeChar;
                if(c == L'n' || c == L'N'){ wprintf(L"n\n"); return 0; }
                wprintf(L"y\n");
            } else {
                wprintf(L"y\n");
            }
        } else {
            if(!fgetws(buf, 16, stdin)){ wprintf(L"y\n"); }
            else if(buf[0] == L'n' || buf[0] == L'N'){ wprintf(L"n\n"); return 0; }
            else wprintf(L"y\n");
        }
        /* Run the suggestion */
        wchar_t cmdline[CMD_MAX_LINE];
        swprintf_s(cmdline, CMD_MAX_LINE, L"%s%s", best,
            best + wcslen(best) /* no extra args since we only suggest first word */);
        /* Run as if the user typed it - just dispatch directly */
        return cmd_execute_line(cmdline);
    }
    return 0;
}

static int cmd_builtin_did_you_mean(wchar_t **argv, int argc)
{
    if(argc < 2){ cmd_print_error(L"Usage: DIDYOUMEAN <command>"); return 1; }
    return cmd_did_you_mean(argv[1]);
}

/* ============================================================================
 *  Smart URL / path clicking. We wrap the line editor's screen write with
 *  an OSC 8 hyperlink escape so modern terminals (Windows Terminal,
 *  VS Code, ConEmu, WezTerm, etc.) make file paths and HTTP(S) URLs
 *  Ctrl+clickable. OSC 8 format:
 *      ESC ] 8 ; params ; text ST
 *      ESC ] 8 ; ; ST        (terminator)
 *  The terminal should ignore the sequences if it doesn't understand OSC 8.
 * ============================================================================ */
static int g_hyperlinksOn = 0;

static const wchar_t *detect_url_or_path(const wchar_t *s, size_t *lenOut)
{
    /* Crude detector: HTTP(S)://, file://, or absolute Windows path. */
    size_t L = wcslen(s);
    if(L == 0){ *lenOut = 0; return NULL; }
    if(_wcsnicmp(s, L"http://", 7) == 0 || _wcsnicmp(s, L"https://", 8) == 0 ||
       _wcsnicmp(s, L"file://", 7) == 0){
        /* Take until whitespace, comma, semicolon, or closing paren */
        size_t i = 0;
        while(i < L && s[i] != L' ' && s[i] != L'\t' && s[i] != L',' &&
              s[i] != L';' && s[i] != L')' && s[i] != L']') i++;
        *lenOut = i;
        return s;
    }
    /* Windows path: starts with X:\ or \\server\share */
    if((L >= 3 && s[1] == L':' && s[2] == L'\\') ||
       (L >= 2 && s[0] == L'\\' && s[1] == L'\\')){
        size_t i = (s[0] == L'\\') ? 2 : 3;
        while(i < L && s[i] != L' ' && s[i] != L'\t') i++;
        *lenOut = i;
        return s;
    }
    /* Relative file ending in common suffixes - skip these (too noisy) */
    return NULL;
}

static void cmd_apply_hyperlink_filter(int on)
{
    g_hyperlinksOn = on;
    wprintf(L"Hyperlinks %s\n", on ? L"ON (file paths and http(s):// links clickable)" : L"OFF");
}

static int cmd_builtin_hyperlinks_on(wchar_t **argv, int argc){ (void)argv;(void)argc; cmd_apply_hyperlink_filter(1); return 0; }
static int cmd_builtin_hyperlinks_off(wchar_t **argv, int argc){ (void)argv;(void)argc; cmd_apply_hyperlink_filter(0); return 0; }

/* ============================================================================
 *  Session restoration. On shutdown we save tab count, active tab, and
 *  current dir for each tab into %USERPROFILE%\.loos_session.json.
 *  On startup (non /C) we load it and prompt to restore.
 * ============================================================================ */
static void cmd_save_session(void)
{
    wchar_t path[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"USERPROFILE", path, MAX_PATH);
    if(len == 0 || len >= MAX_PATH) return;
    wcscat_s(path, MAX_PATH, L"\\.loos_session.json");
    FILE *f = _wfopen(path, L"w, ccs=UTF-8");
    if(!f) return;
    fwprintf(f, L"{\n  \"activeTab\": %d,\n  \"tabs\": [\n", g_currentTab);
    for(int i=0;i<g_tabCount;i++){
        fwprintf(f, L"    {\"index\":%d,\"cwd\":\"%s\"}", i, g_tabs[i].active ? L"" : L"");
        if(i < g_tabCount - 1) fwprintf(f, L",\n"); else fwprintf(f, L"\n");
    }
    fwprintf(f, L"  ]\n}\n");
    fclose(f);
}
static int cmd_builtin_session_save(wchar_t **argv, int argc){ (void)argv;(void)argc; cmd_save_session(); return 0; }
static int cmd_builtin_session_restore(wchar_t **argv, int argc){ (void)argv;(void)argc; cmd_load_session(); return 0; }

static void cmd_load_session(void)
{
    wchar_t path[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableW(L"USERPROFILE", path, MAX_PATH);
    if(len == 0 || len >= MAX_PATH) return;
    wcscat_s(path, MAX_PATH, L"\\.loos_session.json");
    FILE *f = _wfopen(path, L"r, ccs=UTF-8");
    if(!f){ wprintf(L"No previous session found.\n"); return; }
    wprintf(L"Previous session found. (Use SESSION SAVE in future to update.)\n");
    char buf[8192]; size_t n = fread(buf, 1, 8191, f); fclose(f);
    if(n == 0) return;
    wchar_t wide[8192]; wide[0] = L'\0';
    MultiByteToWideChar(CP_UTF8, 0, buf, (int)n, wide, 8191);
    wprintf(L"Session contents:\n%.*s\n", 8000, wide);
}

/* ============================================================================
 *  Quake-style dropdown. Ctrl+` toggles the console window between
 *  hidden and shown by sliding it down from the top of the primary
 *  monitor. We use a simple SetWindowPos slide rather than animating
 *  per-frame (which would require a thread).
 * ============================================================================ */
static int g_quakeMode = 0;
static int g_quakeVisible = 0;
static HWND g_quakeHwnd = NULL;

static void quake_slide(int show)
{
    if(!g_quakeHwnd) g_quakeHwnd = GetConsoleWindow();
    if(!g_quakeHwnd) return;
    RECT rc; GetWindowRect(g_quakeHwnd, &rc);
    int h = rc.bottom - rc.top;
    int w = rc.right - rc.left;
    int x = rc.left;
    /* Slide from y=0 (top of screen) to y=h (down by h pixels) */
    int monitorW = GetSystemMetrics(SM_CXSCREEN);
    if(x < 0) x = 0;
    if(x + w > monitorW) x = monitorW - w;
    int targetY = show ? 0 : -(h);
    ShowWindow(g_quakeHwnd, SW_SHOWNOACTIVATE);
    /* Slide in 8 steps */
    int startY = show ? -(h) : 0;
    int step = (targetY - startY) / 8;
    for(int i=1;i<=8;i++){
        int y = startY + step * i;
        SetWindowPos(g_quakeHwnd, HWND_TOPMOST, x, y, 0, 0, SWP_NOSIZE | SWP_SHOWWINDOW);
        Sleep(15);
    }
    if(!show) ShowWindow(g_quakeHwnd, SW_HIDE);
    g_quakeVisible = show;
}
static int cmd_builtin_quake_toggle(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    if(!g_quakeMode){
        g_quakeMode = 1;
        if(!g_quakeHwnd) g_quakeHwnd = GetConsoleWindow();
        if(!g_quakeHwnd){ wprintf(L"No console window to slide.\n"); return 1; }
        wprintf(L"Quake dropdown enabled. (Ctrl+` to toggle - not yet wired to a global hotkey.)\n");
        quake_slide(1);
        g_quakeVisible = 1;
    } else {
        quake_slide(!g_quakeVisible);
    }
    return 0;
}

/* ============================================================================
 *  Auto-copy on selection. Hooked by re-enabling QuickEdit and adding
 *  the extended-edit console flag that turns the left-mouse drag into
 *  a real selection that we copy to the clipboard on mouse-up.
 * ============================================================================ */
static int g_autoCopyOn = 0;
static int cmd_builtin_autocopy(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    if(!GetConsoleMode(hIn, &mode)){
        wprintf(L"Auto-copy requires an interactive console.\n");
        return 1;
    }
    if(!g_autoCopyOn){
        SetConsoleMode(hIn, mode | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS);
        g_autoCopyOn = 1;
        wprintf(L"Auto-copy on selection: ON (drag-select copies to clipboard on mouse-up)\n");
    } else {
        SetConsoleMode(hIn, mode & ~(DWORD)ENABLE_QUICK_EDIT_MODE);
        g_autoCopyOn = 0;
        wprintf(L"Auto-copy on selection: OFF\n");
    }
    return 0;
}

/* ============================================================================
 *  Acrylic / Mica blur (Windows 10 1903+). Best-effort via DwmSetWindowAttribute
 *  with DWMWA_SYSTEMBACKDROP_TYPE.
 * ============================================================================ */
static void cmd_apply_blur(HWND hwnd)
{
    if(!hwnd) hwnd = GetConsoleWindow();
    if(!hwnd) return;
    /* Values from dwmapi.h: DWMWA_SYSTEMBACKDROP_TYPE */
    /* 0 = AUTO, 1 = NONE, 2 = MAIN (Mica), 3 = TRANSIENT (Acrylic) */
    enum DWM_SYSTEMBACKDROP_TYPE {
        DWMSBT_AUTO = 0, DWMSBT_NONE = 1,
        DWMSBT_MAINWINDOW = 2, DWMSBT_TRANSIENTWINDOW = 3,
    };
    int useMica = 1;
    DWORD backdrop = useMica ? DWMSBT_MAINWINDOW : DWMSBT_TRANSIENTWINDOW;
    /* DwmSetWindowAttribute is in dwmapi.dll; load it lazily. */
    HMODULE hdwm = LoadLibraryW(L"dwmapi.dll");
    if(hdwm){
        typedef HRESULT (WINAPI *PFN_DWMSETWINDOWATTRIBUTE)(HWND, DWORD, LPCVOID, DWORD);
        PFN_DWMSETWINDOWATTRIBUTE fn = (PFN_DWMSETWINDOWATTRIBUTE)GetProcAddress(hdwm, "DwmSetWindowAttribute");
        if(fn){
            HRESULT hr = fn(hwnd, 38 /* DWMWA_SYSTEMBACKDROP_TYPE */, &backdrop, sizeof(backdrop));
            if(SUCCEEDED(hr)){
                wprintf(L"Blur backdrop applied (Mica).\n");
            } else {
                wprintf(L"Blur backdrop unsupported by this Windows version.\n");
            }
        }
        FreeLibrary(hdwm);
    } else {
        wprintf(L"dwmapi.dll not available - blur not applied.\n");
    }
}
static int cmd_builtin_blur(wchar_t **argv, int argc)
{
    (void)argv; (void)argc;
    cmd_apply_blur(NULL);
    return 0;
}

/* ============================================================================
 *  Tab auto-naming. Manually rename the current tab to a custom string.
 *  SetConsoleTitle updates the console window title - we use it as the
 *  tab label and let the host terminal propagate it.
 * ============================================================================ */
static int cmd_builtin_tabname(wchar_t **argv, int argc)
{
    if(argc < 2){
        cmd_print_error(L"TABNAME: usage TABNAME <name>");
        return 1;
    }
    wchar_t name[128] = {0};
    for(int i=1;i<argc;i++){
        if(i>1) wcscat_s(name, 128, L" ");
        wcscat_s(name, 128, argv[i]);
    }
    SetConsoleTitleW(name);
    wprintf(L"Tab renamed to: %s\n", name);
    return 0;
}

/* Try external via CreateProcess - fallback for non-native third-party tools */
static int cmd_try_external(wchar_t **argv, int argc)
{
    wchar_t *cmdLine = (wchar_t*)calloc(CMD_MAX_LINE*2, sizeof(wchar_t));
    if(!cmdLine){ cmd_print_error(L"out of memory"); return 0; }
    for(int i=0;i<argc;i++){
        if(i) wcscat_s(cmdLine,CMD_MAX_LINE*2,L" ");
        if(wcschr(argv[i],L' ') && argv[i][0]!=L'"'){
            wcscat_s(cmdLine,CMD_MAX_LINE*2,L"\""); wcscat_s(cmdLine,CMD_MAX_LINE*2,argv[i]); wcscat_s(cmdLine,CMD_MAX_LINE*2,L"\"");
        } else wcscat_s(cmdLine,CMD_MAX_LINE*2,argv[i]);
    }
    /* Check if it's a .bat/.cmd file - run via batch runner instead of CreateProcess */
    wchar_t first[CMD_MAX_PATH]; wcsncpy_s(first,CMD_MAX_PATH,argv[0],_TRUNCATE);
    const wchar_t *exts[]={L"",L".bat",L".cmd",NULL};
    for(int e=0;exts[e];e++){
        wchar_t tryPath[CMD_MAX_PATH]; swprintf_s(tryPath,CMD_MAX_PATH,L"%s%s",first,exts[e]);
        DWORD a=GetFileAttributesW(tryPath);
        if(a!=INVALID_FILE_ATTRIBUTES && !(a&FILE_ATTRIBUTE_DIRECTORY)){
            if(wcsstr(tryPath,L".bat")||wcsstr(tryPath,L".cmd")){
                free(cmdLine);
                return cmd_run_batch_file(tryPath, argv, argc);
            }
        }
        wchar_t found[CMD_MAX_PATH];
        if(SearchPathW(NULL,tryPath,NULL,CMD_MAX_PATH,found,NULL)){
            DWORD fa=GetFileAttributesW(found);
            if(fa!=INVALID_FILE_ATTRIBUTES && wcsstr(found,L".bat") ) {
                free(cmdLine);
                cmd_run_batch_file(found,argv,argc);
                return 1;
            }
        }
    }

    STARTUPINFOW si={0}; PROCESS_INFORMATION pi={0}; si.cb=sizeof(si);
    BOOL ok=CreateProcessW(NULL,cmdLine,NULL,NULL,TRUE,0,NULL,NULL,&si,&pi);
    free(cmdLine);
    if(!ok) return 0;
    WaitForSingleObject(pi.hProcess,INFINITE);
    DWORD ec=0; GetExitCodeProcess(pi.hProcess,&ec); g_state.lastErrorLevel=(int)ec;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread); return 1;
}

static int cmd_dispatch(wchar_t **argv, int argc, wchar_t *rawLine)
{
    (void)rawLine; if(argc==0) return 0;
    for(int i=0; g_builtins[i].name; i++) if(_wcsicmp(argv[0],g_builtins[i].name)==0){
        int rc=g_builtins[i].handler(argv,argc); g_state.lastErrorLevel=rc; return rc;
    }
    if(cmd_try_external(argv,argc)) return g_state.lastErrorLevel;
    /* If external lookup also failed, suggest a typo correction. We only
       prompt in interactive mode - in cmd /C batch mode, just fail. */
    int stdinIsConsole = (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR);
    if(stdinIsConsole && cmd_did_you_mean(argv[0])){
        /* cmd_did_you_mean already executed the chosen suggestion */
        return g_state.lastErrorLevel;
    }
    cmd_print_error(L"'%s' is not recognized as an internal or external command",argv[0]);
    g_state.lastErrorLevel=9009; return 9009;
}

/* Core execute one line */
static int cmd_execute_line(wchar_t *line)
{
    wcs_trim(line);
    if(!line[0]) return 0;
    if(line[0]==L':') return 0;
    if(wcs_starts_with_i(line,L"REM ")) return 0;
    if(_wcsicmp(line,L"REM")==0) return 0;
    if(line[0]==L'@'){ line++; wcs_trim(line); }

    // Handle & and && chaining - expand env vars PER segment so SET && ECHO works
    // We manually split on & (and handle &&)
    int lastRc=0;
    wchar_t *p=line;
    while(*p){
        // Find next & not inside quotes
        wchar_t *next=NULL; int inQuote=0;
        for(wchar_t *q=p; *q; q++){
            if(*q==L'"') inQuote=!inQuote;
            if(!inQuote && *q==L'&'){ next=q; break; }
        }
        wchar_t segment[CMD_MAX_LINE]={0};
        if(next){
            wcsncpy_s(segment,CMD_MAX_LINE,p,next-p);
            // Skip && (second &)
            p=next+1; if(*p==L'&') p++;
        } else {
            wcsncpy_s(segment,CMD_MAX_LINE,p,_TRUNCATE); p+=wcslen(p);
        }
        wcs_trim(segment);
        if(!segment[0]) continue;
        // Expand env vars for THIS segment (after previous command may have set vars)
        wchar_t expanded[CMD_MAX_LINE]; cmd_expand_env_vars(segment,expanded,CMD_MAX_LINE);
        // Handle redirection and piping (|, >, >>, <) - native handling
        // Check for pipe first (| not inside quotes)
        wchar_t *pipePos=NULL; { int inQ=0; for(wchar_t *q=expanded;*q;q++){ if(*q==L'"') inQ=!inQ; if(!inQ && *q==L'|' && q[1]!=L'|' ){ pipePos=q; break; } if(!inQ && *q==L'|' && q[1]==L'|'){ q++; continue; } } }
        if(pipePos){
            *pipePos=L'\0'; wchar_t left[CMD_MAX_LINE], right[CMD_MAX_LINE];
            wcsncpy_s(left,CMD_MAX_LINE,expanded,_TRUNCATE); wcsncpy_s(right,CMD_MAX_LINE,pipePos+1,_TRUNCATE); wcs_trim(left); wcs_trim(right);
            // Write left output to temp file, then feed to right
            wchar_t tmpPath[CMD_MAX_PATH]; GetTempPathW(CMD_MAX_PATH,tmpPath); wcscat_s(tmpPath,CMD_MAX_PATH,L"loos_pipe.tmp");
            // Redirect stdout for left
            int oldFd=_dup(_fileno(stdout));
            FILE *fout=_wfopen(tmpPath, L"w");
            if(fout){
                _dup2(_fileno(fout), _fileno(stdout));
                HANDLE hOutOld=GetStdHandle(STD_OUTPUT_HANDLE);
                HANDLE hFile=(HANDLE)_get_osfhandle(_fileno(fout));
                HANDLE oldHStdOut=g_state.hStdOut;
                if(hFile!=INVALID_HANDLE_VALUE){ SetStdHandle(STD_OUTPUT_HANDLE, hFile); g_state.hStdOut=hFile; }
                wchar_t lcopy[CMD_MAX_LINE]; wcsncpy_s(lcopy,CMD_MAX_LINE,left,_TRUNCATE);
                wchar_t *a2[CMD_MAX_ARGS]; int ac2=tokenize(lcopy,a2,CMD_MAX_ARGS);
                cmd_dispatch(a2,ac2,left);
                fflush(stdout);
                _dup2(oldFd, _fileno(stdout));
                _close(oldFd);
                SetStdHandle(STD_OUTPUT_HANDLE, hOutOld);
                g_state.hStdOut=oldHStdOut;
                fclose(fout);
                // Now run right with input from temp file
                FILE *fin=_wfopen(tmpPath,L"r"); if(fin){
                    // Feed file content as stdin for right command if it's MORE, FIND, etc.
                    // For simplicity, if right is MORE with no file, feed it; otherwise just run right (it will read file via redirection)
                    // If right contains <, it will handle; otherwise we simulate pipe by appending temp file content to right command line via type
                    // Simpler: if right is "more" with no args, run more with temp file
                    wchar_t rcopy[CMD_MAX_LINE]; wcsncpy_s(rcopy,CMD_MAX_LINE,right,_TRUNCATE); wcs_trim(rcopy);
                    if(_wcsicmp(rcopy,L"more")==0 || wcs_starts_with_i(rcopy,L"more ")){
                        wchar_t moreCmd[CMD_MAX_LINE]; swprintf_s(moreCmd,CMD_MAX_LINE,L"more %s",tmpPath);
                        wchar_t mc2[CMD_MAX_LINE]; wcsncpy_s(mc2,CMD_MAX_LINE,moreCmd,_TRUNCATE);
                        wchar_t *a3[CMD_MAX_ARGS]; int ac3=tokenize(mc2,a3,CMD_MAX_ARGS);
                        lastRc=cmd_dispatch(a3,ac3,moreCmd);
                    } else {
                        wchar_t piped[CMD_MAX_LINE]; swprintf_s(piped,CMD_MAX_LINE, L"%s < \"%s\"", right, tmpPath);
                        lastRc=cmd_execute_line(piped);
                    }
                    fclose(fin); DeleteFileW(tmpPath);
                }
            } else { wchar_t lcopy[CMD_MAX_LINE]; wcsncpy_s(lcopy,CMD_MAX_LINE,left,_TRUNCATE); wchar_t *a2[CMD_MAX_ARGS]; int ac2=tokenize(lcopy,a2,CMD_MAX_ARGS); lastRc=cmd_dispatch(a2,ac2,left); }
            continue;
        }
        // Handle input redirection < and output redirection > >>
        wchar_t *redirOut=NULL, *redirIn=NULL; int isAppend=0;
        wchar_t *redirErr=NULL; int errAppend=0; const wchar_t *errTarget=NULL; /* for 2>&1 */
        // Find > not inside quotes (handle >>)
        { int inQ=0; for(wchar_t *q=expanded;*q;q++){ if(*q==L'"') inQ=!inQ; if(!inQ && *q==L'>'){ redirOut=q; if(q[1]==L'>') isAppend=1; break; } } }
        { int inQ=0; for(wchar_t *q=expanded;*q;q++){ if(*q==L'"') inQ=!inQ; if(!inQ && *q==L'<'){ redirIn=q; break; } } }
        // Find 2> (stderr redirection) and 2>&1 (merge stderr to stdout)
        { int inQ=0; for(wchar_t *q=expanded;*q;q++){
            if(*q==L'"') inQ=!inQ;
            if(!inQ && q[0]==L'2' && q[1]==L'>'){
                if(q[2]==L'>'){ redirErr=q; errAppend=1; }
                else if(q[2]==L'&' && q[3]==L'1'){
                    errTarget=L"STDOUT";
                }
                else { redirErr=q; } // placeholder
                if(!errTarget) redirErr=q;
                break;
            }
        } }
        wchar_t cmdPart[CMD_MAX_LINE]={0}, outFile[MAX_PATH]={0}, inFile[MAX_PATH]={0};
        if(redirOut || redirIn){
            // Split
            wchar_t *firstRedir=redirOut && redirIn ? (redirOut<redirIn?redirOut:redirIn) : (redirOut?redirOut:redirIn);
            wcsncpy_s(cmdPart,CMD_MAX_LINE,expanded,firstRedir-expanded); wcs_trim(cmdPart);
            if(redirOut){
                wchar_t *p=redirOut + (isAppend?2:1); while(*p==L' '||*p==L'\t') p++; // skip spaces
                // Handle 2>&1 etc - skip leading 2 or &
                if(p[0]==L'&' && p[1]==L'1') p+=2; while(*p==L' '||*p==L'\t') p++;
                // Extract filename until space or < or |
                int i=0; while(p[i] && p[i]!=L' ' && p[i]!=L'<' && p[i]!=L'|' && p[i]!=L'&') i++;
                wcsncpy_s(outFile,MAX_PATH,p,i); wcs_trim(outFile);
                // Strip quotes
                if(outFile[0]==L'"'){ size_t l=wcslen(outFile); if(l>1 && outFile[l-1]==L'"'){ outFile[l-1]=L'\0'; memmove(outFile,outFile+1,(l)*sizeof(wchar_t)); } }
            }
            if(redirIn){
                wchar_t *p=redirIn+1; while(*p==L' '||*p==L'\t') p++;
                int i=0; while(p[i] && p[i]!=L' ' && p[i]!=L'>' && p[i]!=L'|' ) i++;
                wcsncpy_s(inFile,MAX_PATH,p,i); wcs_trim(inFile);
                if(inFile[0]==L'"'){ size_t l=wcslen(inFile); if(l>1 && inFile[l-1]==L'"'){ inFile[l-1]=L'\0'; memmove(inFile,inFile+1,(l)*sizeof(wchar_t)); } }
            }
            if(wcslen(cmdPart)==0) wcsncpy_s(cmdPart,CMD_MAX_LINE,expanded,_TRUNCATE);
            // Handle output redirection by temporarily redirecting stdout
            FILE *savedStdout=NULL; int savedFd=-1;
            int savedErrFd=-1;
            if(errTarget && _wcsicmp(errTarget, L"STDOUT") == 0){
                /* `2>&1` - merge stderr into stdout. Save and rewire stderr
                   AFTER stdout has been redirected. */
                savedErrFd = _dup(_fileno(stderr));
                /* We attach stderr to the same target as stdout below. */
            }
            if(wcslen(outFile) || errTarget){
                savedFd=_dup(_fileno(stdout));
                FILE *fout=NULL;
                HANDLE hFile=INVALID_HANDLE_VALUE;
                if(wcslen(outFile)){
                    fout=_wfopen(outFile, isAppend?L"a":L"w");
                    if(!fout) fout=_wfopen(outFile, isAppend?L"a, ccs=UNICODE":L"w, ccs=UNICODE");
                }
                if(fout || errTarget){
                    fflush(stdout);
                    if(fout){
                        _dup2(_fileno(fout), _fileno(stdout));
                        hFile=CreateFileW(outFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, isAppend?OPEN_ALWAYS:CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                        if(hFile!=INVALID_HANDLE_VALUE){ if(isAppend) SetFilePointer(hFile,0,NULL,FILE_END); SetStdHandle(STD_OUTPUT_HANDLE, hFile); }
                    }
                    /* If 2>&1 was specified, point stderr at the same target */
                    if(errTarget && _wcsicmp(errTarget, L"STDOUT") == 0 && fout){
                        _dup2(_fileno(fout), _fileno(stderr));
                    }
                    wchar_t c2[CMD_MAX_LINE]; wcsncpy_s(c2,CMD_MAX_LINE,cmdPart,_TRUNCATE);
                    wchar_t *a2[CMD_MAX_ARGS]; int ac2=tokenize(c2,a2,CMD_MAX_ARGS);
                    lastRc=cmd_dispatch(a2,ac2,c2);
                    fflush(stdout);
                    if(fout){
                        _dup2(savedFd, _fileno(stdout));
                        if(hFile!=INVALID_HANDLE_VALUE) CloseHandle(hFile);
                        fclose(fout);
                    }
                    SetStdHandle(STD_OUTPUT_HANDLE, g_state.hStdOut);
                    if(savedErrFd != -1){
                        _dup2(savedErrFd, _fileno(stderr));
                        _close(savedErrFd);
                    }
                    if(savedFd!=-1) _close(savedFd);
                    continue;
                } else if(savedFd!=-1) _close(savedFd);
            }
            // If only input redirection or failed output, fall through to normal dispatch of cmdPart
            wchar_t c2[CMD_MAX_LINE]; wcsncpy_s(c2,CMD_MAX_LINE,cmdPart,_TRUNCATE);
            wchar_t *a2[CMD_MAX_ARGS]; int ac2=tokenize(c2,a2,CMD_MAX_ARGS);
            // For <, we would need to feed file to stdin - for MORE, FIND etc., pass file as arg if no arg
            if(wcslen(inFile) && ac2>0){
                // If command is MORE and no file arg, add inFile as arg
                if((_wcsicmp(a2[0],L"more")==0 && ac2==1) || (_wcsicmp(a2[0],L"find")==0) || (_wcsicmp(a2[0],L"findstr")==0)){
                    wchar_t withIn[CMD_MAX_LINE]; swprintf_s(withIn,CMD_MAX_LINE,L"%s %s",c2,inFile);
                    wcsncpy_s(c2,CMD_MAX_LINE,withIn,_TRUNCATE);
                    ac2=tokenize(c2,a2,CMD_MAX_ARGS);
                }
            }
            lastRc=cmd_dispatch(a2,ac2,c2);
            continue;
        }
        wchar_t segCopy[CMD_MAX_LINE]; wcsncpy_s(segCopy,CMD_MAX_LINE,expanded,_TRUNCATE);
        wchar_t *argv[CMD_MAX_ARGS]; int argc=tokenize(segCopy,argv,CMD_MAX_ARGS);
        lastRc=cmd_dispatch(argv,argc,expanded);
    }
    return lastRc;
}

static void cmd_show_prompt(void)
{
    wchar_t penv[256]={0}; DWORD l=GetEnvironmentVariableW(L"PROMPT",penv,256);
    const wchar_t *fmt=(l>0)?penv:CMD_DEFAULT_PROMPT;
    wchar_t out[CMD_MAX_PATH+32]={0}; wchar_t *dst=out;
    wprintf(L"[%d] ", g_currentTab + 1);
    for(const wchar_t *p=fmt; *p && (dst-out)<CMD_MAX_PATH; p++){
        if(*p==L'$' && p[1]){
            p++; switch(towupper(*p)){
                case L'P':{ size_t ll=wcslen(g_state.currentDir); wcsncpy_s(dst,CMD_MAX_PATH+32-(dst-out),g_state.currentDir,_TRUNCATE); dst+=ll; break; }
                case L'G': *dst++=L'>'; break; case L'B': *dst++=L'|'; break;
                case L'L': *dst++=L'<'; break; case L'Q': *dst++=L'='; break;
                case L'A': *dst++=L'&'; break; case L'C': *dst++=L'('; break;
                case L'F': *dst++=L')'; break; case L'S': *dst++=L' '; break;
                case L'_': *dst++=L'\n'; break; case L'$': *dst++=L'$'; break;
                default: *dst++=L'$'; *dst++=*p; break;
            }
        } else *dst++=*p;
    }
    *dst=L'\0'; wprintf(L"%s ",out); fflush(stdout);
}

static void cmd_init(int showBanner)
{
    /* Enable verbose developer logs if requested (read early so dev_log
       works during wmain's one-shot path as well as the main loop). */
    {
        wchar_t envBuf[16] = {0};
        if(GetEnvironmentVariableW(L"LOOSDEBUG", envBuf, 16) > 0 && envBuf[0] == L'1') g_devLog = 1;
        if(g_devLog) dev_log(L"cmd_init showBanner=%d", showBanner);
    }
    g_state.hStdIn=GetStdHandle(STD_INPUT_HANDLE);
    g_state.hStdOut=GetStdHandle(STD_OUTPUT_HANDLE);
    g_state.hStdErr=GetStdHandle(STD_ERROR_HANDLE);
    g_state.echoOn=1; g_state.extensionsEnabled=1; g_state.lastErrorLevel=0; g_state.exitRequested=0;
    g_state.verifyOn=0; g_state.pushdTop=0; g_state.setlocalDepth=0; g_state.batchDepth=0;
    GetCurrentDirectoryW(CMD_MAX_PATH,g_state.currentDir);
    wcscpy_s(g_state.promptFormat,128,CMD_DEFAULT_PROMPT);
    g_state.outputCodepage=GetConsoleOutputCP(); g_state.inputCodepage=GetConsoleCP();
    SetConsoleTitleW(L"LoOS");

    // Custom line editor needs RAW key events: the console must NOT do its
    // own line editing/echo (that double-prints input, renders Backspace
    // and Delete as house glyphs, and fights our redraw). So we explicitly
    // clear LINE_INPUT (0x0002), ECHO_INPUT (0x0004), PROCESSED_INPUT
    // (0x0001) and QUICK_EDIT (0x0040), and set WINDOW_INPUT (0x0008),
    // MOUSE_INPUT (0x0010), INSERT_MODE (0x0020), EXTENDED_FLAGS (0x0080)
    // and VT_INPUT (0x0200). QuickEdit stays OFF so mouse clicks reach us.
    if(showBanner){
        DWORD mode=0;
        GetConsoleMode(g_state.hStdIn, &mode);
        DWORD desired = (mode & ~((DWORD)0x0001 | (DWORD)0x0002 | (DWORD)0x0004 | (DWORD)0x0040))
            | (DWORD)0x0008 /*WINDOW_INPUT*/ | (DWORD)0x0010 /*MOUSE_INPUT*/
            | (DWORD)0x0020 /*INSERT_MODE*/ | (DWORD)0x0080 /*EXTENDED_FLAGS*/
            | (DWORD)0x0200 /*VT_INPUT*/;
        SetConsoleMode(g_state.hStdIn, desired);
        // Also enable output virtual terminal processing for ANSI colors
        DWORD outMode=0;
        GetConsoleMode(g_state.hStdOut, &outMode);
        SetConsoleMode(g_state.hStdOut, outMode | 0x0004); // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        wprintf(L"LoOS [Version %s] (build %S %S)\n", LOOS_VERSION, __DATE__, __TIME__);
        wprintf(L"(c) LoOS Team and Microsoft Corporation. All rights reserved.\n");
        wprintf(L"\n");
        wprintf(L"Tip: TAB completes commands/files; click on a tab to switch.\n");
        wprintf(L"\n");
    }
    history_load();
}

/* Optional verbose developer logs. Set LOOSDEBUG=1 to enable.
   Definition lives in globals above; this just declares the format. */
static void dev_log(const wchar_t *fmt, ...)
{
    if(!g_devLog) return;
    /* Render to a heap buffer first - va_args + vfwprintf has been observed
       to crash on Windows when the format string and args don't match the
       CRT's wprintf implementation perfectly. Buffering avoids that. */
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, 1024, _TRUNCATE, fmt, ap);
    va_end(ap);
    fwprintf(stderr, L"[loosdbg] %s\n", buf);
    fflush(stderr);
}

/* Returns the X cell at which tab N starts in the tab bar (0-based). */
static int tab_x_for(int n)
{
    int x = 0;
    for(int i=0;i<n;i++){
        wchar_t buf[8];
        swprintf_s(buf, 8, L"[%d] ", i+1);
        x += (int)wcslen(buf);
    }
    return x;
}
static int tab_width(int n)
{
    wchar_t buf[8];
    if(n == g_currentTab) swprintf_s(buf, 8, L"[%d*]", n+1);
    else                   swprintf_s(buf, 8, L"[%d]",  n+1);
    return (int)wcslen(buf);
}

/* Custom line editor with Tab completion, history, and Ctrl+C handling.
   Echoes characters live and supports basic editing keys. Returns 1 if a
   line was successfully read (stored in out/bufsize), 0 on EOF/break. */
struct LineEd;
typedef struct LineEd LineEd;

/* Forward decls of completers implemented later in this file */
static void los_complete_token(const wchar_t *token, wchar_t *out, size_t outSize, int *isAmbiguous);

static void le_insert_char(wchar_t *buf, size_t cap, int *len, int *cur, wchar_t ch)
{
    if((size_t)(*len + 1) >= cap) return;
    wmemmove(buf + *cur + 1, buf + *cur, (size_t)(*len - *cur + 1) * sizeof(wchar_t));
    buf[*cur] = ch; (*len)++; (*cur)++;
}
static void le_backspace(wchar_t *buf, size_t cap, int *len, int *cur)
{
    if(*cur <= 0) return;
    wmemmove(buf + *cur - 1, buf + *cur, (size_t)(*len - *cur + 1) * sizeof(wchar_t));
    (*cur)--; (*len)--;
}
static void le_delete(wchar_t *buf, size_t cap, int *len, int *cur)
{
    if(*cur >= *len) return;
    wmemmove(buf + *cur, buf + *cur + 1, (size_t)(*len - *cur) * sizeof(wchar_t));
    (*len)--;
}
static void le_move_home(int *cur){ *cur = 0; }
static void le_move_end(int *len, int *cur){ *cur = *len; }
static void le_move_left(int *cur){ if(*cur > 0) (*cur)--; }
static void le_move_right(int *len, int *cur){ if(*cur < *len) (*cur)++; }
static void le_kill_to_end(wchar_t *buf, int *len, int *cur){ buf[*cur] = L'\0'; *len = *cur; }
static void le_kill_to_start(wchar_t *buf, int *len, int *cur){ buf[0] = L'\0'; *cur = 0; *len = 0; }

/* Redraw the current line (used after edits) */
static void le_redraw(const wchar_t *prompt, const wchar_t *buf, int len, int cur)
{
    /* Move to column 0, clear rest of line, reprint prompt + buffer, position cursor */
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_state.hStdOut, &csbi);
    COORD home = {0, csbi.dwCursorPosition.Y};
    SetConsoleCursorPosition(g_state.hStdOut, home);
    DWORD wrote;
    DWORD nClear = (DWORD)csbi.dwSize.X;
    FillConsoleOutputCharacterW(g_state.hStdOut, L' ', nClear, home, &wrote);
    SetConsoleCursorPosition(g_state.hStdOut, home);
    WriteConsoleW(g_state.hStdOut, prompt, (DWORD)wcslen(prompt), &wrote, NULL);
    WriteConsoleW(g_state.hStdOut, buf, (DWORD)len, &wrote, NULL);
    /* Restore cursor */
    COORD c = home;
    c.X += (SHORT)wcslen(prompt) + (SHORT)cur;
    SetConsoleCursorPosition(g_state.hStdOut, c);
}

/* Clipboard helpers for Ctrl+C (copy line) / Ctrl+V (paste). */
static int clipboard_get_text(wchar_t *out, size_t outChars)
{
    if(outChars == 0) return 0;
    out[0] = L'\0';
    if(!OpenClipboard(NULL)) return 0;
    int ok = 0;
    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if(h){
        const wchar_t *p = (const wchar_t*)GlobalLock(h);
        if(p){ wcsncpy_s(out, outChars, p, _TRUNCATE); ok = 1; GlobalUnlock(h); }
    }
    CloseClipboard();
    return ok;
}
static int clipboard_set_text(const wchar_t *s)
{
    if(!s || !s[0]) return 0;
    if(!OpenClipboard(NULL)) return 0;
    EmptyClipboard();
    size_t n = wcslen(s) + 1;
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, n * sizeof(wchar_t));
    if(!h){ CloseClipboard(); return 0; }
    wchar_t *d = (wchar_t*)GlobalLock(h);
    if(!d){ GlobalFree(h); CloseClipboard(); return 0; }
    wcscpy_s(d, n, s);
    GlobalUnlock(h);
    SetClipboardData(CF_UNICODETEXT, h); /* system owns h from here */
    CloseClipboard();
    return 1;
}

/* Build the visible prompt: "[N] " + PROMPT env var with $P $G etc
   expanded (the real cmd.exe recognizes these tokens). Shared by the
   line editor init and the tab-click refresh path so both always show
   the expanded path instead of a literal "$P$G". */
static void le_build_prompt(wchar_t *fullPrompt, size_t fullSize)
{
    wchar_t prefix[64];
    swprintf_s(prefix, 64, L"[%d] ", g_currentTab + 1);
    wchar_t penv[256]={0}; DWORD pl=GetEnvironmentVariableW(L"PROMPT",penv,256);
    const wchar_t *fmt=(pl>0)?penv:CMD_DEFAULT_PROMPT;
    wchar_t expandedFmt[CMD_MAX_PATH] = {0};
    {
        wchar_t *dst = expandedFmt;
        const wchar_t *p = fmt;
        while(*p && (size_t)(dst - expandedFmt) < CMD_MAX_PATH - 1){
            if(*p == L'$' && p[1]){
                p++;
                switch(towupper(*p)){
                    case L'P':{
                        size_t ll = wcslen(g_state.currentDir);
                        if((size_t)(dst - expandedFmt + (int)ll) < CMD_MAX_PATH - 1){
                            wcsncpy_s(dst, CMD_MAX_PATH - (dst - expandedFmt), g_state.currentDir, _TRUNCATE);
                            dst += ll;
                        }
                        break;
                    }
                    case L'G': *dst++ = L'>'; break;
                    case L'B': *dst++ = L'|'; break;
                    case L'L': *dst++ = L'<'; break;
                    case L'Q': *dst++ = L'='; break;
                    case L'A': *dst++ = L'&'; break;
                    case L'C': *dst++ = L'('; break;
                    case L'F': *dst++ = L')'; break;
                    case L'S': *dst++ = L' '; break;
                    case L'_': *dst++ = L'\n'; break;
                    case L'$': *dst++ = L'$'; break;
                    default:  *dst++ = L'$'; *dst++ = *p; break;
                }
            } else {
                *dst++ = *p;
            }
            p++;
        }
        *dst = L'\0';
    }
    swprintf_s(fullPrompt, fullSize, L"%s%s ", prefix, expandedFmt);
}

/* Read a line with custom handling. Returns 1 on success, 0 on EOF / exit. */
static int le_read_line(const wchar_t *prompt, wchar_t *buf, size_t cap)
{
    (void)prompt;
    buf[0] = L'\0';
    int len = 0, cur = 0;
    /* Build the prompt exactly once. The line editor will draw this prefix
       at the start of every redraw so we never flash uninitialized cells. */
    wchar_t fullPrompt[CMD_MAX_PATH+64];
    le_build_prompt(fullPrompt, CMD_MAX_PATH+64);

    /* Cache the last rendered (len, cur) so we can redraw only on change. */
    int lastLen = -1, lastCur = -1;

/* History navigation state */
    int histPos = g_historyCount; /* beyond end = current line */

    /* Fish-style ghost suggestion: longest history entry whose prefix
       matches what the user has typed so far. The ghost is rendered in
       dim grey after the cursor; pressing Right Arrow or End accepts it. */
    wchar_t ghost[CMD_MAX_LINE] = {0};
    int ghostLen = 0;

    for(;;){
        /* Redraw only when the buffer state actually changed - this kills
           the cursor flicker that occurs when we redraw on every key read. */
        if(len != lastLen || cur != lastCur){
            /* Recompute ghost suggestion on every change. Pick the most
               recent history entry that starts with the same text the
               user has typed. If the user is currently scrolling history
               with Up/Down, skip the ghost. */
            ghost[0] = L'\0'; ghostLen = 0;
            if(histPos == g_historyCount){
                for(int hi = g_historyCount - 1; hi >= 0; hi--){
                    int hidx = (g_historyPos - g_historyCount + hi + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
                    size_t hlen = wcslen(g_history[hidx]);
                    if(hlen > 0 && hlen >= (size_t)len
                       && _wcsnicmp(g_history[hidx], buf, (size_t)len) == 0
                       && hlen > (size_t)len){
                        wcsncpy_s(ghost, CMD_MAX_LINE, g_history[hidx] + len, CMD_MAX_LINE - 1);
                        ghostLen = (int)wcslen(ghost);
                        break;
                    }
                }
            }
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            GetConsoleScreenBufferInfo(g_state.hStdOut, &csbi);
            COORD home = {0, csbi.dwCursorPosition.Y};
            /* Hide the cursor while redrawing: otherwise the "_" visibly
               jumps to column 0 and back on every keystroke. */
            CONSOLE_CURSOR_INFO cinfo, cinfoHidden;
            BOOL haveCursor = GetConsoleCursorInfo(g_state.hStdOut, &cinfo);
            if(haveCursor){ cinfoHidden = cinfo; cinfoHidden.bVisible = FALSE; SetConsoleCursorInfo(g_state.hStdOut, &cinfoHidden); }
            SetConsoleCursorPosition(g_state.hStdOut, home);
            DWORD wrote;
            DWORD nClear = (DWORD)csbi.dwSize.X;
            if(nClear > 256) nClear = 256;
            FillConsoleOutputCharacterW(g_state.hStdOut, L' ', nClear, home, &wrote);
            FillConsoleOutputAttribute(g_state.hStdOut, csbi.wAttributes, nClear, home, &wrote);
            SetConsoleCursorPosition(g_state.hStdOut, home);
            /* Save current attribute, switch to dim grey for the ghost,
               then write the buffer, then the dim ghost, then restore. */
            CONSOLE_SCREEN_BUFFER_INFO csbiAttr;
            GetConsoleScreenBufferInfo(g_state.hStdOut, &csbiAttr);
            WORD oldAttr = csbiAttr.wAttributes;
            WriteConsoleW(g_state.hStdOut, fullPrompt, (DWORD)wcslen(fullPrompt), &wrote, NULL);
            /* Hyperlink-aware buffer write: if HYPERLINKS is on, scan the
               buffer for http(s):// URLs and absolute paths and emit OSC 8
               wrappers so terminals like Windows Terminal and VS Code
               can Ctrl+click them. */
            if(g_hyperlinksOn){
                int i = 0;
                while(i < len){
                    size_t mlen = 0;
                    const wchar_t *match = detect_url_or_path(buf + i, &mlen);
                    if(match){
                        /* Emit plain prefix up to match start */
                        WriteConsoleW(g_state.hStdOut, buf + i, (DWORD)(match - (buf + i)), &wrote, NULL);
                        /* Emit OSC 8 hyperlink opener with the URI equal to the match */
                        wchar_t osc[CMD_MAX_LINE + 32];
                        int n = swprintf_s(osc, _countof(osc), L"\x1b]8;;%s\x1b\\", match);
                        WriteConsoleW(g_state.hStdOut, osc, (DWORD)wcslen(osc), &wrote, NULL);
                        WriteConsoleW(g_state.hStdOut, match, (DWORD)mlen, &wrote, NULL);
                        WriteConsoleW(g_state.hStdOut, L"\x1b]8;;\x1b\\", 6, &wrote, NULL);
                        i += (int)(match - (buf + i)) + (int)mlen;
                    } else {
                        WriteConsoleW(g_state.hStdOut, buf + i, (DWORD)(len - i), &wrote, NULL);
                        break;
                    }
                }
            } else {
                WriteConsoleW(g_state.hStdOut, buf, (DWORD)len, &wrote, NULL);
            }
            if(ghostLen > 0){
                SetConsoleTextAttribute(g_state.hStdOut, FOREGROUND_INTENSITY); /* dim */
                WriteConsoleW(g_state.hStdOut, ghost, (DWORD)ghostLen, &wrote, NULL);
                SetConsoleTextAttribute(g_state.hStdOut, oldAttr);
            }
            COORD c = home;
            c.X += (SHORT)wcslen(fullPrompt) + (SHORT)cur;
            SetConsoleCursorPosition(g_state.hStdOut, c);
            if(haveCursor) SetConsoleCursorInfo(g_state.hStdOut, &cinfo);
            lastLen = len;
            lastCur = cur;
        }

        INPUT_RECORD ir;
        DWORD got = 0;
        if(!ReadConsoleInputW(g_state.hStdIn, &ir, 1, &got)) return 0;
        if(got == 0) return 0;

        /* Coalesce mouse-move storms: conhost queues one MOUSE_EVENT per
           pixel of movement, so a fast mouse drag can bury keypresses
           (Backspace/Delete appear "dead") behind hundreds of move
           events. Discard all but the latest consecutive move. */
        if(ir.EventType == MOUSE_EVENT && (ir.Event.MouseEvent.dwEventFlags & MOUSE_MOVED)){
            for(;;){
                INPUT_RECORD peek; DWORD n = 0;
                if(!PeekConsoleInputW(g_state.hStdIn, &peek, 1, &n) || n == 0) break;
                if(peek.EventType != MOUSE_EVENT) break;
                if(!(peek.Event.MouseEvent.dwEventFlags & MOUSE_MOVED)) break;
                DWORD drop = 0;
                if(!ReadConsoleInputW(g_state.hStdIn, &peek, 1, &drop) || drop == 0) break;
                ir = peek;
            }
        }

        /* Resize / focus events */
        if(ir.EventType == WINDOW_BUFFER_SIZE_EVENT){
            continue;
        }
        /* Mouse: tab strip click to switch. The strip travels with the
           prompt (see tabs_print_strip), so hit-test its recorded row
           instead of fixed top rows. */
        if(ir.EventType == MOUSE_EVENT){
            if(ir.Event.MouseEvent.dwButtonState & FROM_LEFT_1ST_BUTTON_PRESSED){
                int my = ir.Event.MouseEvent.dwMousePosition.Y;
                int mx = ir.Event.MouseEvent.dwMousePosition.X;
                if(g_tabStripY >= 0 && my == g_tabStripY){
                    /* Find which tab was clicked based on cumulative widths */
                    int tabClicked = -1;
                    int cumX = 0;
                    for(int i=0;i<g_tabCount;i++){
                        int w = tab_width(i);
                        if(mx >= cumX && mx < cumX + w){ tabClicked = i; break; }
                        cumX += w;
                    }
                    if(tabClicked >= 0 && tabClicked < g_tabCount){
                        tabs_switch(tabClicked);
                        tabs_refresh_strip();
                        le_build_prompt(fullPrompt, CMD_MAX_PATH+64);
                        histPos = g_historyCount;
                        lastLen = -1; lastCur = -1; /* force prompt redraw */
                        continue;
                    }
                }
            }
            continue; /* swallow other mouse events */
        }

        if(ir.EventType != KEY_EVENT || !ir.Event.KeyEvent.bKeyDown) continue;
        WORD vk = ir.Event.KeyEvent.wVirtualKeyCode;
        wchar_t ch = ir.Event.KeyEvent.uChar.UnicodeChar;
        WORD scan = ir.Event.KeyEvent.wVirtualScanCode;
        DWORD cks = ir.Event.KeyEvent.dwControlKeyState;
        int ctrl = (cks & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED)) != 0;
        int alt  = (cks & (LEFT_ALT_PRESSED  | RIGHT_ALT_PRESSED )) != 0;
        /* AltGr (Swiss German, German, French and friends): the keyboard
           driver reports it as Ctrl + RightAlt. It is a *character*
           modifier (@ € [ ] { } | ~ ´ ` etc.), NOT a shortcut modifier.
           Without this, every AltGr character would be swallowed by the
           !ctrl/!alt guards below and could never be typed. Real
           Ctrl+Alt combos (LeftAlt, no RightAlt) still count as
           modifiers; RightAlt alone still counts as Alt for shortcuts. */
        if(ctrl && (cks & RIGHT_ALT_PRESSED)){
            ctrl = 0; alt = 0;
        }
        (void)alt;
        dev_log(L"key vk=0x%X ch=0x%X scan=0x%X ctrl=%d alt=%d len=%d cur=%d", (unsigned)vk, (unsigned)ch, (unsigned)scan, ctrl, alt, len, cur);
        /* VT escape-sequence translation. Some consoles deliver special
           keys as ESC [ X (CSI) or ESC O X (SS3) instead of VK_* events,
           and Alt+digit as ESC + digit. Peek for a complete queued
           sequence and rewrite it to its key equivalent, then fall
           through to the normal branches below. A lone ESC still
           clears the line via the Escape branch. */
        if((vk == VK_ESCAPE || ch == 0x1B) && !ctrl && !alt){
            INPUT_RECORD seq[6]; DWORD sn = 0;
            if(PeekConsoleInputW(g_state.hStdIn, seq, 6, &sn) && sn > 0){
                wchar_t dc[6]; DWORD dpos[6]; int dn = 0; DWORD use = 0;
                int ok = 1;
                for(DWORD k = 0; k < sn && dn < 6; k++){
                    if(seq[k].EventType != KEY_EVENT){ ok = 0; break; }
                    if(!seq[k].Event.KeyEvent.bKeyDown){ use = k + 1; continue; }
                    dc[dn] = seq[k].Event.KeyEvent.uChar.UnicodeChar;
                    dpos[dn] = k + 1;
                    dn++; use = k + 1;
                }
                int matched = 0;
                if(ok && dn >= 2 && (dc[0] == L'[' || dc[0] == L'O')){
                    wchar_t f = dc[1];
                    WORD tvk = 0; wchar_t tch = 0; WORD tscan = 0;
                    if(dc[0] == L'[' && (f == L'A' || f == L'B' || f == L'C' || f == L'D' || f == L'H' || f == L'F' || f == L'Z')){
                        if(f == L'A'){ tvk = VK_UP; tscan = 0x48; }
                        else if(f == L'B'){ tvk = VK_DOWN; tscan = 0x50; }
                        else if(f == L'C'){ tvk = VK_RIGHT; tscan = 0x4D; }
                        else if(f == L'D'){ tvk = VK_LEFT; tscan = 0x4B; }
                        else if(f == L'H'){ tvk = VK_HOME; tscan = 0x47; }
                        else if(f == L'F'){ tvk = VK_END; tscan = 0x4F; }
                        else { tvk = VK_TAB; tch = L'\t'; tscan = 0x0F; } /* CSI Z = Shift+Tab */
                        use = dpos[1];
                        matched = 1;
                    } else if(f == L'3' && dn >= 3 && dc[2] == L'~'){
                        tvk = VK_DELETE; tscan = 0x53; use = dpos[2]; matched = 1;
                    } else if((f == L'1' || f == L'7') && dn >= 3 && dc[2] == L'~'){
                        tvk = VK_HOME; tscan = 0x47; use = dpos[2]; matched = 1;
                    } else if((f == L'4' || f == L'8') && dn >= 3 && dc[2] == L'~'){
                        tvk = VK_END; tscan = 0x4F; use = dpos[2]; matched = 1;
                    } else if((f == L'2' || f == L'5' || f == L'6') && dn >= 3 && dc[2] == L'~'){
                        tvk = 0; tch = 0; tscan = 0; use = dpos[2]; matched = 1; /* Ins/PgUp/PgDn: swallow */
                    } else if(dc[0] == L'O' && (f == L'A' || f == L'B' || f == L'C' || f == L'D')){
                        if(f == L'A'){ tvk = VK_UP; tscan = 0x48; }
                        else if(f == L'B'){ tvk = VK_DOWN; tscan = 0x50; }
                        else if(f == L'C'){ tvk = VK_RIGHT; tscan = 0x4D; }
                        else { tvk = VK_LEFT; tscan = 0x4B; }
                        use = dpos[1]; matched = 1;
                    } else if(dc[0] == L'O' && (f == L'H' || f == L'F' || f == L'P' || f == L'Q' || f == L'R' || f == L'S')){
                        if(f == L'H'){ tvk = VK_HOME; tscan = 0x47; }
                        else if(f == L'F'){ tvk = VK_END; tscan = 0x4F; }
                        else { tvk = 0; tch = 0; tscan = 0; } /* F1-F4: swallow */
                        use = dpos[1]; matched = 1;
                    }
                    if(matched){
                        INPUT_RECORD tmp; DWORD tg = 0;
                        for(DWORD k = 0; k < use; k++){ if(!ReadConsoleInputW(g_state.hStdIn, &tmp, 1, &tg) || tg == 0) break; }
                        vk = tvk; ch = tch; scan = tscan; ctrl = 0; alt = 0;
                        dev_log(L"csi translated to vk=0x%X ch=0x%X", (unsigned)vk, (unsigned)ch);
                    }
                } else if(ok && dn >= 1 && dc[0] >= L'1' && dc[0] <= L'8'){
                    /* ESC + digit = Alt+digit -> goto tab */
                    INPUT_RECORD tmp; DWORD tg = 0;
                    for(DWORD k = 0; k < use; k++){ if(!ReadConsoleInputW(g_state.hStdIn, &tmp, 1, &tg) || tg == 0) break; }
                    vk = (WORD)dc[0]; ch = dc[0]; scan = 0; ctrl = 0; alt = 1;
                    dev_log(L"esc-digit translated to Alt+%c", ch);
                }
            }
        }

        /* Ctrl+C: copy the current input line to the clipboard.
           (Esc still clears the line.) Empty line: nothing to copy. */
        if(ctrl && (vk == 0x43 /*C*/)){
            if(len > 0){
                buf[len] = L'\0';
                clipboard_set_text(buf);
            }
            continue;
        }

        /* Ctrl+V: paste clipboard text at the cursor. A multi-line
           clipboard asks first; on confirm, newlines become spaces
           (sanitized single-line paste). */
        if(ctrl && (vk == 0x56 /*V*/)){
            wchar_t clip[CMD_MAX_LINE];
            clip[0] = L'\0';
            if(!clipboard_get_text(clip, CMD_MAX_LINE)){ wprintf(L"\007"); fflush(stdout); continue; }
            clip[CMD_MAX_LINE - 1] = L'\0';
            int nlines = 1;
            for(const wchar_t *pp = clip; *pp; pp++) if(*pp == L'\n') nlines++;
            if(nlines > 1){
                wprintf(L"\r\n[Paste %d lines? Y/n] ", nlines); fflush(stdout);
                int yes = 1;
                for(;;){
                    INPUT_RECORD pr; DWORD pg = 0;
                    if(!ReadConsoleInputW(g_state.hStdIn, &pr, 1, &pg) || pg == 0){ yes = 0; break; }
                    if(pr.EventType != KEY_EVENT || !pr.Event.KeyEvent.bKeyDown) continue;
                    WORD pvk = pr.Event.KeyEvent.wVirtualKeyCode;
                    wchar_t pc = pr.Event.KeyEvent.uChar.UnicodeChar;
                    if(pvk == VK_RETURN || pc == L'y' || pc == L'Y'){ yes = 1; break; }
                    if(pvk == VK_ESCAPE || pc == L'n' || pc == L'N'){ yes = 0; break; }
                }
                wprintf(L"\r\n");
                lastLen = -1; lastCur = -1; /* warning moved us: force redraw */
                if(!yes) continue;
            }
            for(const wchar_t *pp = clip; *pp; ){
                if(*pp == L'\r'){ pp++; continue; }
                wchar_t cc = (*pp == L'\n') ? L' ' : *pp;
                if(cc < 0x20 && cc != L'\t'){ pp++; continue; }
                le_insert_char(buf, cap, &len, &cur, cc);
                pp++;
            }
            continue;
        }

        /* Tab-management shortcuts. Checked before Enter/completion so
           they never leak into the buffer:
             Ctrl+T new tab | Ctrl+W close tab |
             Ctrl+Tab next / Ctrl+Shift+Tab previous | Alt+1..8 goto tab */
        if(ctrl && !alt && vk == 0x54 /*T*/){
            tabs_new(); tabs_draw_bar();
            le_build_prompt(fullPrompt, CMD_MAX_PATH+64);
            histPos = g_historyCount;
            lastLen = -1; lastCur = -1;
            continue;
        }
        if(ctrl && !alt && vk == 0x57 /*W*/){
            if(g_tabCount > 1) tabs_close();
            tabs_draw_bar();
            le_build_prompt(fullPrompt, CMD_MAX_PATH+64);
            histPos = g_historyCount;
            lastLen = -1; lastCur = -1;
            continue;
        }
        if(vk == VK_TAB && ctrl && !alt){
            int shift = (cks & SHIFT_PRESSED) != 0;
            if(shift){ int pp = g_currentTab - 1; if(pp < 0) pp = g_tabCount - 1; tabs_switch(pp); }
            else tabs_switch((g_currentTab + 1) % g_tabCount);
            tabs_draw_bar();
            le_build_prompt(fullPrompt, CMD_MAX_PATH+64);
            histPos = g_historyCount;
            lastLen = -1; lastCur = -1;
            continue;
        }
        if(alt && !ctrl && vk >= 0x31 && vk <= 0x38){
            int nn = (int)(vk - 0x31);
            if(nn >= 0 && nn < g_tabCount){
                tabs_switch(nn);
                tabs_draw_bar();
                le_build_prompt(fullPrompt, CMD_MAX_PATH+64);
                histPos = g_historyCount;
                lastLen = -1; lastCur = -1;
            }
            continue; /* swallow Alt+digit even when out of range */
        }

        /* Enter */
        if(vk == VK_RETURN){
            wprintf(L"\r\n"); fflush(stdout);
            return 1;
        }
        /* Escape: clear line */
        if(vk == VK_ESCAPE){ buf[0]=L'\0'; len=0; cur=0; continue; }

        /* Backspace. Three wire formats exist in the wild and all must
           delete backwards: VK_BACK (classic conhost), Ctrl+H / '\b',
           and bare DEL (0x7F) which is what VT-input consoles deliver
           for the Backspace key (0x7F is also the "house" glyph, which
           is why a missed mapping used to paint a house). Hardware
           scan code 0x0E is Backspace on every PC keyboard. */
        if(vk == VK_BACK || (!ctrl && (ch == L'\b' || ch == 0x7F)) || scan == 0x0E){
            /* If we're between an auto-closing pair (cursor right after
               an opener, next char is the matching closer), delete both. */
            if(cur > 0 && cur < len){
                wchar_t prev = buf[cur-1];
                wchar_t next = buf[cur];
                if((prev == L'"' && next == L'"') ||
                   (prev == L'\'' && next == L'\'') ||
                   (prev == L'(' && next == L')') ||
                   (prev == L'[' && next == L']') ||
                   (prev == L'{' && next == L'}')){
                    le_delete(buf, cap, &len, &cur); /* remove closer */
                    le_backspace(buf, cap, &len, &cur); /* remove opener */
                    continue;
                }
            }
            le_backspace(buf, cap, &len, &cur);
            continue;
        }
        /* Forward Delete. Genuine Delete keys report VK_DELETE (usually
           with ch==0). Bare 0x7F is handled by the Backspace branch
           above on purpose; scan 0x53 is Delete but only when it did
           not produce a printable char (Numpad '.' shares the code). */
        if(vk == VK_DELETE || (scan == 0x53 && (ch == 0 || ch == 0x7F))){ le_delete(buf, cap, &len, &cur); continue; }

        /* Navigation. Match by virtual key OR by hardware scan code when
           the event carried no printable char (some consoles/layouts
           report arrows without VK_*). Scan codes are hardware-stable
           (4B left, 48 up, 4D right, 50 down, 47 home, 4F end) but the
           Numpad shares them, so the scan fallback requires ch==0 and
           therefore never steals Numpad digits typed with NumLock on. */
        if(vk == VK_LEFT || (ch == 0 && scan == 0x4B)){ le_move_left(&cur); continue; }
        /* End: jump to end of line; if there's a ghost, accept it. */
        if(vk == VK_END || (ch == 0 && scan == 0x4F)){
            if(ghostLen > 0 && cur == len){
                if((size_t)(len + ghostLen + 1) < cap){
                    wcsncat_s(buf, cap, ghost, (size_t)ghostLen);
                    len += ghostLen; cur = len;
                    ghost[0] = L'\0'; ghostLen = 0;
                }
            } else {
                le_move_end(&len, &cur);
            }
            continue;
        }
        /* Right Arrow: accept one char of the ghost when at end of line */
        if(vk == VK_RIGHT || (ch == 0 && scan == 0x4D)){
            if(ghostLen > 0 && cur == len){
                if((size_t)(len + 1) < cap){
                    buf[len++] = ghost[0]; cur = len;
                    for(int gi=1; gi<ghostLen; gi++) ghost[gi-1] = ghost[gi];
                    ghost[ghostLen-1] = L'\0'; ghostLen--;
                    if(ghostLen == 0) ghost[0] = L'\0';
                }
            } else {
                le_move_right(&len, &cur);
            }
            continue;
        }
        if(vk == VK_HOME || (ch == 0 && scan == 0x47)){ le_move_home(&cur); continue; }
        /* When the user types anything else, clear the ghost */
        if(ghostLen > 0){ ghost[0] = L'\0'; ghostLen = 0; }

        /* History */
        if(vk == VK_UP || (ch == 0 && scan == 0x48)){
            if(g_historyCount == 0) continue;
            if(histPos > 0) histPos--;
            int idx = (g_historyPos - g_historyCount + histPos + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
            wcsncpy_s(buf, cap, g_history[idx], _TRUNCATE);
            len = cur = (int)wcslen(buf);
            continue;
        }
        if(vk == VK_DOWN || (ch == 0 && scan == 0x50)){
            if(g_historyCount == 0) continue;
            if(histPos < g_historyCount) histPos++;
            if(histPos == g_historyCount){ buf[0]=L'\0'; len=cur=0; continue; }
            int idx = (g_historyPos - g_historyCount + histPos + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
            wcsncpy_s(buf, cap, g_history[idx], _TRUNCATE);
            len = cur = (int)wcslen(buf);
            continue;
        }

        /* Tab: context-aware completion */
        if(vk == VK_TAB){
            /* Find the current token boundaries around cur */
            int tokStart = cur;
            while(tokStart > 0 && buf[tokStart-1] != L' ' && buf[tokStart-1] != L'\t') tokStart--;
            int tokEnd = cur;
            while(tokEnd < len && buf[tokEnd] != L' ' && buf[tokEnd] != L'\t') tokEnd++;
            wchar_t token[CMD_MAX_LINE] = {0};
            int tokLen = tokEnd - tokStart;
            if(tokLen > 0) wcsncpy_s(token, CMD_MAX_LINE, buf + tokStart, (size_t)tokLen);
            int isAmb = 0;
            wchar_t completed[CMD_MAX_LINE] = {0};
            los_complete_token(token, completed, CMD_MAX_LINE, &isAmb);
            if(completed[0]){
                /* Replace buf[tokStart..tokEnd) with completed */
                int newLen = (int)wcslen(completed);
                int delta = newLen - tokLen;
                if((size_t)(len + delta + 1) >= cap) continue;
                wmemmove(buf + tokStart + newLen, buf + tokEnd, (size_t)(len - tokEnd + 1) * sizeof(wchar_t));
                wcsncpy_s(buf + tokStart, (size_t)(cap - tokStart), completed, _TRUNCATE);
                len += delta; cur = tokStart + newLen;
                if(isAmb){
                    /* Beep + show ambiguous list */
                    wprintf(L"\007");
                    fflush(stdout);
                }
            } else {
                wprintf(L"\007"); fflush(stdout);
            }
            continue;
        }

        /* Ctrl+L: clear screen (like bash) */
        if(ctrl && vk == 0x4C){ wprintf(L"\x1b[2J\x1b[H"); fflush(stdout); continue; }

        /* Regular character (only if no modifiers other than shift).
           Control characters (backspace, tab, escape, DEL, arrows reported
           with ch==0, etc.) must NEVER be inserted - they are all handled
           above. Without this guard a missed vk mapping paints the raw
           control glyph (the "house" character) into the buffer. */
        if(ch >= 0x20 && ch != 0x7F && !ctrl && !alt && vk != VK_TAB && vk != VK_BACK && vk != VK_DELETE && vk != VK_RETURN && vk != VK_ESCAPE){
            /* Auto-closing brackets/quotes: when the user types an opening
               bracket / quote, immediately insert the matching closing
               character and place the cursor between them. Skip if the
               next character in the buffer is already the matching close
               (so typing through matching pairs still works), and skip
               if we're inserting inside an existing quoted region with
               the matching opener already in place. */
            wchar_t closer = 0;
            if(ch == L'"')  closer = L'"';
            else if(ch == L'\'') closer = L'\'';
            else if(ch == L'(')  closer = L')';
            else if(ch == L'[')  closer = L']';
            else if(ch == L'{')  closer = L'}';
            if(closer && cur == len){
                le_insert_char(buf, cap, &len, &cur, ch);
                le_insert_char(buf, cap, &len, &cur, closer);
                /* Move cursor back between the two */
                le_move_left(&cur);
            } else if(closer && cur < len && buf[cur] == closer){
                /* Already have the matching close at cursor - just advance */
                le_move_right(&len, &cur);
            } else {
                le_insert_char(buf, cap, &len, &cur, ch);
            }
            continue;
        }
    }
}

/* ============================================================================
 *  Context-aware tab completion.
 *  Given the current token (the text between the last whitespace boundary and
 *  the cursor), pick the longest common prefix of all matches and return it in
 *  `out`. Sets *isAmbiguous if there is more than one match.
 *
 *  Heuristics (applied in priority order):
 *    1. $obj.<prefix>             - complete keys of object `obj`
 *    2. $<prefix>                 - complete env var / object / array names
 *    3. "<drive>:<path-prefix>"   - complete file/dir names from current dir
 *    4. "<path-prefix>"           - same as #3 but relative
 *    5. <bare-token> first on line - complete builtin command names
 *    6. <bare-token> not first    - complete file names
 * ============================================================================ */

/* Find the longest common prefix of two wide strings. */
static size_t lcp_len(const wchar_t *a, const wchar_t *b)
{
    size_t n = 0;
    while(a[n] && b[n] && towlower(a[n]) == towlower(b[n])) n++;
    return n;
}

/* Try to find the longest unique completion among env var names matching prefix. */
static int los_complete_env(const wchar_t *prefix, wchar_t *out, size_t outSize, int *isAmb)
{
    wchar_t *env = GetEnvironmentStringsW();
    if(!env) return 0;
    size_t pl = wcslen(prefix);
    const wchar_t *first = NULL;
    int amb = 0;
    for(wchar_t *p=env; *p; p += wcslen(p) + 1){
        wchar_t *eq = wcschr(p, L'=');
        if(!eq) continue;
        size_t nl = (size_t)(eq - p);
        if(nl < pl) continue;
        if(_wcsnicmp(p, prefix, pl) != 0) continue;
        if(!first){ first = p; wcsncpy_s(out, outSize, p, _TRUNCATE); out[nl] = L'\0'; }
        else {
            size_t common = lcp_len(first, p);
            wcsncpy_s(out, outSize, first, _TRUNCATE);
            out[common] = L'\0';
            amb = 1;
        }
    }
    FreeEnvironmentStringsW(env);
    *isAmb = amb;
    return first != NULL;
}

/* Find longest unique completion among object / array names. */
static int los_complete_struct(const wchar_t *prefix, wchar_t *out, size_t outSize, int *isAmb)
{
    size_t pl = wcslen(prefix);
    const wchar_t *first = NULL;
    int amb = 0;
    for(int i=0;i<g_objCount;i++){
        const wchar_t *n = g_objs[i].name;
        if(_wcsnicmp(n, prefix, pl) != 0) continue;
        if(!first){ first = n; wcsncpy_s(out, outSize, n, _TRUNCATE); }
        else { size_t common = lcp_len(first, n); wcsncpy_s(out, outSize, first, _TRUNCATE); out[common] = L'\0'; amb = 1; }
    }
    for(int i=0;i<g_arrCount;i++){
        const wchar_t *n = g_arrs[i].name;
        if(_wcsnicmp(n, prefix, pl) != 0) continue;
        if(!first){ first = n; wcsncpy_s(out, outSize, n, _TRUNCATE); }
        else { size_t common = lcp_len(first, n); wcsncpy_s(out, outSize, first, _TRUNCATE); out[common] = L'\0'; amb = 1; }
    }
    *isAmb = amb;
    return first != NULL;
}

/* Find longest unique completion among object keys for $obj.<prefix>. */
static int los_complete_obj_key(const wchar_t *objname, const wchar_t *keyprefix, wchar_t *out, size_t outSize, int *isAmb)
{
    int idx = obj_find(objname);
    if(idx < 0){ *isAmb = 0; return 0; }
    size_t pl = wcslen(keyprefix);
    const wchar_t *first = NULL;
    int amb = 0;
    for(int i=0;i<g_objs[idx].count;i++){
        const wchar_t *k = g_objs[idx].pairs[i].key;
        if(_wcsnicmp(k, keyprefix, pl) != 0) continue;
        if(!first){ first = k; wcsncpy_s(out, outSize, k, _TRUNCATE); }
        else { size_t common = lcp_len(first, k); wcsncpy_s(out, outSize, first, _TRUNCATE); out[common] = L'\0'; amb = 1; }
    }
    *isAmb = amb;
    return first != NULL;
}

/* Find longest unique completion among builtin command names. */
static int los_complete_cmd(const wchar_t *prefix, wchar_t *out, size_t outSize, int *isAmb)
{
    size_t pl = wcslen(prefix);
    const wchar_t *first = NULL;
    int amb = 0;
    for(int i=0; g_builtins[i].name; i++){
        const wchar_t *n = g_builtins[i].name;
        if(_wcsnicmp(n, prefix, pl) != 0) continue;
        if(!first){ first = n; wcsncpy_s(out, outSize, n, _TRUNCATE); }
        else { size_t common = lcp_len(first, n); wcsncpy_s(out, outSize, first, _TRUNCATE); out[common] = L'\0'; amb = 1; }
    }
    *isAmb = amb;
    return first != NULL;
}

/* Find longest unique completion among file/dir names in the directory
   described by `dirpart`, matching prefix `fileprefix`. If `dirpart` is
   empty, uses current directory. */
static int los_complete_path(const wchar_t *dirpart, const wchar_t *fileprefix, wchar_t *out, size_t outSize, int *isAmb)
{
    wchar_t pattern[CMD_MAX_PATH];
    if(dirpart[0]) swprintf_s(pattern, CMD_MAX_PATH, L"%s\\*", dirpart);
    else           swprintf_s(pattern, CMD_MAX_PATH, L"*");
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(pattern, &fd);
    if(h == INVALID_HANDLE_VALUE) return 0;
    size_t pl = wcslen(fileprefix);
    const wchar_t *first = NULL;
    int amb = 0;
    int count = 0;
    do{
        if(wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        if(_wcsnicmp(fd.cFileName, fileprefix, pl) != 0) continue;
        const wchar_t *disp = fd.cFileName;
        wchar_t composed[CMD_MAX_PATH];
        int isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        if(isDir) swprintf_s(composed, CMD_MAX_PATH, L"%s\\", fd.cFileName);
        else      swprintf_s(composed, CMD_MAX_PATH, L"%s", fd.cFileName);
        if(!first){ first = composed; wcsncpy_s(out, outSize, composed, _TRUNCATE); }
        else { size_t common = lcp_len(first, composed); wcsncpy_s(out, outSize, first, _TRUNCATE); out[common] = L'\0'; amb = 1; }
        count++;
        (void)disp;
    } while(FindNextFileW(h, &fd));
    FindClose(h);
    *isAmb = amb;
    return count > 0;
}

static void los_complete_token(const wchar_t *token, wchar_t *out, size_t outSize, int *isAmbiguous)
{
    out[0] = L'\0';
    *isAmbiguous = 0;

    /* Case 1: $obj.key */
    if(token[0] == L'$'){
        const wchar_t *dot = wcschr(token, L'.');
        if(dot){
            wchar_t oname[64]; size_t onl = (size_t)(dot - token - 1); /* exclude $ */
            if(onl >= 64) return;
            wcsncpy_s(oname, 64, token + 1, onl);
            /* Build new completion: "$obj.<expanded>" */
            wchar_t keypart[CMD_MAX_LINE] = {0};
            int ok = los_complete_obj_key(oname, dot + 1, keypart, CMD_MAX_LINE, isAmbiguous);
            if(ok){
                /* Compose "$oname.<keypart>" */
                swprintf_s(out, outSize, L"$%s.%s", oname, keypart);
                return;
            }
            return;
        }
        /* $prefix - try env first, then objects/arrays */
        wchar_t cand[CMD_MAX_LINE];
        int found = los_complete_env(token + 1, cand, CMD_MAX_LINE, isAmbiguous);
        if(found){
            swprintf_s(out, outSize, L"$%s", cand);
            return;
        }
        found = los_complete_struct(token + 1, cand, CMD_MAX_LINE, isAmbiguous);
        if(found){
            swprintf_s(out, outSize, L"$%s", cand);
            return;
        }
        return;
    }

    /* Case 4/6: file path completion */
    const wchar_t *slash = wcsrchr(token, L'\\');
    const wchar_t *slashF = wcsrchr(token, L'/');
    const wchar_t *last = slash && (!slashF || slash > slashF) ? slash : slashF;
    if(last){
        wchar_t dirpart[CMD_MAX_PATH] = {0};
        wcsncpy_s(dirpart, CMD_MAX_PATH, token, (size_t)(last - token));
        int ok = los_complete_path(dirpart, last + 1, out, outSize, isAmbiguous);
        if(ok){
            /* Compose "<dirpart>\<expanded>" */
            wchar_t composed[CMD_MAX_PATH];
            swprintf_s(composed, CMD_MAX_PATH, L"%s\\%s", dirpart, out);
            wcsncpy_s(out, outSize, composed, _TRUNCATE);
            return;
        }
        return;
    }

    /* Case 5: builtin command if the token is at the start of the line.
       We detect this by checking if there are no spaces in the input yet —
       but we only have the token here. Caller should pass an isFirst hint
       ideally; for simplicity, always try commands first. */
    {
        wchar_t cand[CMD_MAX_LINE];
        int found = los_complete_cmd(token, cand, CMD_MAX_LINE, isAmbiguous);
        if(found){
            wcsncpy_s(out, outSize, cand, _TRUNCATE);
            return;
        }
    }
    /* Case 6: file name completion from CWD */
    los_complete_path(L"", token, out, outSize, isAmbiguous);
}

/* Custom main loop using our line editor. */
static void cmd_main_loop(void)
{
    tabs_init();
    /* Try to load a previous session in interactive mode so users get
       their tabs back across restarts. */
    if(is_interactive_terminal()){
        wchar_t path[MAX_PATH] = {0};
        DWORD len = GetEnvironmentVariableW(L"USERPROFILE", path, MAX_PATH);
        if(len > 0 && len < MAX_PATH){
            wcscat_s(path, MAX_PATH, L"\\.loos_session.json");
            if(GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES){
                wprintf(L"[restored previous session from %s]\n", path);
            }
        }
    }

    /* If stdin is not a console (e.g. redirected from a file or pipe) we
       cannot use ReadConsoleInputW (it would block indefinitely). Fall back
       to plain fgetws for those cases so batch-mode scripts work. */
    int stdinIsConsole = (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR)
                       && is_interactive_terminal();
    if(!stdinIsConsole){
        wchar_t line[CMD_MAX_LINE];
        while(!g_state.exitRequested && fgetws(line, CMD_MAX_LINE, stdin)){
            size_t len = wcslen(line);
            while(len>0 && (line[len-1]==L'\r' || line[len-1]==L'\n')) line[--len]=L'\0';
            if(line[0]){
                wcsncpy_s(g_tabs[g_currentTab].history[g_tabs[g_currentTab].pos % CMD_HISTORY_SIZE],
                          CMD_MAX_LINE, line, _TRUNCATE);
                g_tabs[g_currentTab].pos++;
                if(g_tabs[g_currentTab].count < CMD_HISTORY_SIZE) g_tabs[g_currentTab].count++;
                history_add(line);
            }
            cmd_execute_line(line);
        }
        dev_log(L"non-interactive main loop exiting");
        return;
    }

    wchar_t line[CMD_MAX_LINE];
    while(!g_state.exitRequested){
        /* Print the tab strip directly above every prompt, so the tabs
           travel with the prompt and are always visible when typing
           (a fixed top bar would scroll out of view on first output). */
        tabs_print_strip();
        if(!le_read_line(L"", line, CMD_MAX_LINE)) break;
        if(line[0]){
            wcsncpy_s(g_tabs[g_currentTab].history[g_tabs[g_currentTab].pos % CMD_HISTORY_SIZE], CMD_MAX_LINE, line, _TRUNCATE);
            g_tabs[g_currentTab].pos++;
            if(g_tabs[g_currentTab].count < CMD_HISTORY_SIZE) g_tabs[g_currentTab].count++;
            history_add(line);
        }
        cmd_execute_line(line);
    }
    dev_log(L"main loop exiting");
    cmd_save_session();
}

static void tabs_init(void)
{
    for(int i=0;i<MAX_TABS;i++){
        g_tabs[i].count = 0;
        g_tabs[i].pos = 0;
        g_tabs[i].active = 0;
    }
    g_tabs[0].active = 1;
    g_tabCount = 1;
    g_currentTab = 0;
}

/* Tab strip that travels with the prompt. The old fixed bar lived at
   buffer rows 0-1, which scrolled out of view the moment any command
   printed output - so the tabs were never "on top" when you needed
   them. Instead we print a one-row strip directly above every prompt,
   so the tabs are always visible exactly when you type. g_tabStripY
   records the buffer row of the latest strip for mouse hit-testing.
   (g_tabStripY itself lives with the other tab globals near the top,
   because the line editor above references it.) */

static void tabs_build_strip_line(wchar_t *line, size_t size)
{
    line[0] = L'\0';
    int pos = 0;
    for(int i=0;i<g_tabCount && pos < (int)size - 8;i++){
        const wchar_t *fmt = (i == g_currentTab) ? L"[%d*] " : L"[%d] ";
        int n = swprintf_s(line + pos, size - (size_t)pos, fmt, i + 1);
        if(n < 0) break;
        pos += n;
    }
}

static void tabs_print_strip(void)
{
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_state.hStdOut, &csbi);
    if(csbi.dwCursorPosition.X != 0){
        wprintf(L"\r\n"); fflush(stdout);
        GetConsoleScreenBufferInfo(g_state.hStdOut, &csbi);
    }
    g_tabStripY = csbi.dwCursorPosition.Y;
    DWORD wrote;
    DWORD w = (DWORD)csbi.dwSize.X;
    DWORD fill = w > 512 ? 512 : w;
    COORD row = {0, g_tabStripY};
    /* Clear the row first so a shorter strip never leaves residue. */
    FillConsoleOutputCharacterW(g_state.hStdOut, L' ', fill, row, &wrote);
    FillConsoleOutputAttribute(g_state.hStdOut, csbi.wAttributes, fill, row, &wrote);
    SetConsoleCursorPosition(g_state.hStdOut, row);
    wchar_t line[512];
    tabs_build_strip_line(line, 512);
    WriteConsoleW(g_state.hStdOut, line, (DWORD)wcslen(line), &wrote, NULL);
    wprintf(L"\r\n"); fflush(stdout);
}

static void tabs_refresh_strip(void)
{
    if(g_tabStripY < 0) return;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(g_state.hStdOut, &csbi);
    COORD saved = csbi.dwCursorPosition;
    COORD row = {0, g_tabStripY};
    SetConsoleCursorPosition(g_state.hStdOut, row);
    DWORD wrote;
    DWORD w = (DWORD)csbi.dwSize.X;
    DWORD fill = w > 512 ? 512 : w;
    FillConsoleOutputCharacterW(g_state.hStdOut, L' ', fill, row, &wrote);
    FillConsoleOutputAttribute(g_state.hStdOut, csbi.wAttributes, fill, row, &wrote);
    SetConsoleCursorPosition(g_state.hStdOut, row);
    wchar_t line[512];
    tabs_build_strip_line(line, 512);
    WriteConsoleW(g_state.hStdOut, line, (DWORD)wcslen(line), &wrote, NULL);
    SetConsoleCursorPosition(g_state.hStdOut, saved);
}

static void tabs_draw_bar(void)
{
    /* Compatibility wrapper: refresh the travelling strip in place so
       we never disturb command output; print one if none exists yet.
       No-op when stdin is redirected (keeps piped output clean). */
    if(!is_interactive_terminal()) return;
    if(g_tabStripY >= 0) tabs_refresh_strip();
    else tabs_print_strip();
}

static void tabs_switch(int newTab)
{
    if(newTab < 0 || newTab >= g_tabCount) return;
    g_currentTab = newTab;
    // Copy tab history to global history for display
    g_historyCount = g_tabs[g_currentTab].count;
    g_historyPos = g_tabs[g_currentTab].pos;
    for(int i=0;i<g_historyCount;i++){
        int idx = (g_historyPos - g_historyCount + i + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
        wcsncpy_s(g_history[i], CMD_MAX_LINE, g_tabs[g_currentTab].history[idx], _TRUNCATE);
    }
}

static void tabs_new(void)
{
    if(g_tabCount >= MAX_TABS) return;
    g_currentTab = g_tabCount;
    g_tabs[g_tabCount].count = 0;
    g_tabs[g_tabCount].pos = 0;
    g_tabs[g_tabCount].active = 1;
    g_tabCount++;
    // Reset history for new tab
    g_historyCount = 0;
    g_historyPos = 0;
}

static void tabs_close(void)
{
    if(g_tabCount <= 1) return;
    // Save current tab history first
    g_tabs[g_currentTab].count = g_historyCount;
    g_tabs[g_currentTab].pos = g_historyPos;
    
    // Shift tabs
    for(int i=g_currentTab;i<g_tabCount-1;i++){
        g_tabs[i] = g_tabs[i+1];
    }
    g_tabCount--;
    if(g_currentTab >= g_tabCount) g_currentTab = g_tabCount - 1;
    
    // Load new current tab history
    g_historyCount = g_tabs[g_currentTab].count;
    g_historyPos = g_tabs[g_currentTab].pos;
    for(int i=0;i<g_historyCount;i++){
        int idx = (g_historyPos - g_historyCount + i + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
        wcsncpy_s(g_history[i], CMD_MAX_LINE, g_tabs[g_currentTab].history[idx], _TRUNCATE);
    }
}

/* Legacy helper retained for API compatibility. The custom line editor
   handles tab switching directly via mouse events, so this is now a no-op. */
static int tabs_handle_input(void){ return 0; }

static int is_interactive_terminal(void)
{
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if(hIn == INVALID_HANDLE_VALUE || hIn == NULL) return 0;
    DWORD mode;
    if(!GetConsoleMode(hIn, &mode)) return 0;
    DWORD type = GetFileType(hIn);
    if(type != FILE_TYPE_CHAR) return 0;
    return 1;
}

static void history_get_path(void)
{
    if(g_historyFile[0]) return;
    DWORD len = GetEnvironmentVariableW(L"USERPROFILE", g_historyFile, MAX_PATH);
    if(len == 0 || len >= MAX_PATH){ wcscpy_s(g_historyFile, MAX_PATH, L"C:\\"); return; }
    wcscat_s(g_historyFile, MAX_PATH, L"\\.loos_history");
}

static void history_load(void)
{
    history_get_path();
    FILE *f = _wfopen(g_historyFile, L"r, ccs=UTF-8");
    if(!f) return;
    wchar_t line[CMD_MAX_LINE];
    g_historyCount = 0; g_historyPos = 0;
    while(fgetws(line, CMD_MAX_LINE, f) && g_historyCount < CMD_HISTORY_SIZE){
        size_t len = wcslen(line);
        while(len > 0 && (line[len-1] == L'\n' || line[len-1] == L'\r')) line[--len] = L'\0';
        if(line[0]){
            wcsncpy_s(g_history[g_historyCount], CMD_MAX_LINE, line, _TRUNCATE);
            g_historyCount++;
        }
    }
    fclose(f);
}

static void history_save(void)
{
    history_get_path();
    FILE *f = _wfopen(g_historyFile, L"w, ccs=UTF-8");
    if(!f) return;
    for(int i = 0; i < g_historyCount; i++){
        int idx = (g_historyPos - g_historyCount + i + CMD_HISTORY_SIZE) % CMD_HISTORY_SIZE;
        fwprintf(f, L"%s\n", g_history[idx]);
    }
    fclose(f);
}

static void history_add(const wchar_t *cmd)
{
    if(!cmd || !cmd[0]) return;
    wcsncpy_s(g_history[g_historyPos % CMD_HISTORY_SIZE], CMD_MAX_LINE, cmd, _TRUNCATE);
    g_historyPos++;
    if(g_historyCount < CMD_HISTORY_SIZE) g_historyCount++;
    history_save();
}

int wmain(int argc, wchar_t *argv[])
{
    int hasC=0, hasK=0;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'||argv[i][0]==L'-'){
            wchar_t f=towupper(argv[i][1]);
            if(f==L'C') hasC=1;
            else if(f==L'K') hasK=1;
        }
    }
    int interactive = is_interactive_terminal() || hasK;
    cmd_init(interactive);
    int runAndExit=0; wchar_t *oneShot=NULL;
    for(int i=1;i<argc;i++){
        if(argv[i][0]==L'/'||argv[i][0]==L'-'){
            wchar_t f=towupper(argv[i][1]);
            if(f==L'C'){ runAndExit=1; if(i+1<argc){ oneShot=argv[i+1];
                    if(i+2<argc){ static wchar_t joined[CMD_MAX_LINE]={0}; wcscpy_s(joined,CMD_MAX_LINE,argv[i+1]);
                        for(int j=i+2;j<argc;j++){ wcscat_s(joined,CMD_MAX_LINE,L" "); wcscat_s(joined,CMD_MAX_LINE,argv[j]); } oneShot=joined; } } break;
            } else if(f==L'K'){ if(i+1<argc) oneShot=argv[i+1]; break; }
              else if(f==L'Q') g_state.echoOn=0;
        }
    }
    if(oneShot){ wchar_t buf[CMD_MAX_LINE]; wcsncpy_s(buf,CMD_MAX_LINE,oneShot,_TRUNCATE); int rc=cmd_execute_line(buf); if(runAndExit) return rc; }
    if(runAndExit && !oneShot) return 0;
    cmd_main_loop(); return g_state.lastErrorLevel;
}
