/*
 * find_all_keys_macos.c - macOS WeChat memory key scanner
 *
 * Scans WeChat process memory for SQLCipher encryption keys in the
 * x'<key_hex><salt_hex>' format used by WeChat 4.x on macOS.
 *
 * Prerequisites:
 *   - WeChat must be ad-hoc signed (or SIP disabled)
 *   - Must run as root (sudo)
 *
 * Build:
 *   cc -O2 -o find_all_keys_macos find_all_keys_macos.c -framework Foundation
 *
 * Usage:
 *   sudo ./find_all_keys_macos [pid]
 *   If pid is omitted, automatically finds WeChat PID.
 *
 * Output: JSON file at ./all_keys.json (compatible with decrypt_db.py)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <ftw.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <CommonCrypto/CommonCrypto.h>

#define MAX_KEYS 256
#define KEY_SIZE 32
#define SALT_SIZE 16
#define DB_PAGE_SIZE 4096
#define RESERVE_SIZE 80
#define IV_SIZE 16
#define HEX_PATTERN_LEN 96  /* 64 hex (key) + 32 hex (salt) */
#define CHUNK_SIZE (2 * 1024 * 1024)

typedef struct {
    char key_hex[65];
    char salt_hex[33];
    char full_pragma[100];
} key_entry_t;

/* Forward declaration */
static int read_db_page1(const char *path, char *salt_hex_out, unsigned char *page1_out);

/* nftw callback state for collecting DB files */
#define MAX_DBS 256
static char g_db_salts[MAX_DBS][33];
static char g_db_names[MAX_DBS][256];
static unsigned char g_db_pages[MAX_DBS][DB_PAGE_SIZE];
static int g_db_count = 0;
static char g_current_db_dir[768] = "";
static int nftw_collect_db(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf);

static void manual_collect_db_dir(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "  opendir failed (%d): %s\n", errno, dir_path);
        return;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        char child[1024];
        int written = snprintf(child, sizeof(child), "%s/%s", dir_path, entry->d_name);
        if (written < 0 || written >= (int)sizeof(child)) {
            fprintf(stderr, "  SKIP (path too long): %s/%s\n", dir_path, entry->d_name);
            continue;
        }

        struct stat st;
        if (stat(child, &st) != 0) {
            fprintf(stderr, "  stat failed (%d): %s\n", errno, child);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            manual_collect_db_dir(child);
        } else if (S_ISREG(st.st_mode)) {
            size_t len = strlen(child);
            if (len >= 3 && strcmp(child + len - 3, ".db") == 0) {
                printf("  Found candidate: %s\n", child);
                nftw_collect_db(child, &st, FTW_F, NULL);
            }
        }
    }

    closedir(dir);
}

static int nftw_collect_db(const char *fpath, const struct stat *sb,
                           int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_F) return 0;
    size_t len = strlen(fpath);
    if (len < 3 || strcmp(fpath + len - 3, ".db") != 0) return 0;
    if (g_db_count >= MAX_DBS) return 0;

    char salt[33];
    int ret = read_db_page1(fpath, salt, g_db_pages[g_db_count]);
    if (ret != 0) {
        /* Debug: show why this DB was skipped */
        FILE *f = fopen(fpath, "rb");
        if (!f) {
            fprintf(stderr, "  SKIP (cannot open): %s\n", fpath);
        } else {
            unsigned char header[16];
            if (fread(header, 1, 16, f) < 16) {
                fprintf(stderr, "  SKIP (too small): %s\n", fpath);
            } else if (memcmp(header, "SQLite format 3", 15) == 0) {
                fprintf(stderr, "  SKIP (unencrypted): %s\n", fpath);
            } else {
                fprintf(stderr, "  SKIP (read error %d): %s\n", ret, fpath);
            }
            fclose(f);
        }
        return 0;
    }

    strcpy(g_db_salts[g_db_count], salt);
    /* Extract relative path from db_storage/ */
    const char *rel = NULL;
    size_t base_len = strlen(g_current_db_dir);
    if (base_len > 0 && strncmp(fpath, g_current_db_dir, base_len) == 0) {
        rel = fpath + base_len;
        if (*rel == '/') rel++;
    }
    if (!rel || !*rel) {
        rel = strstr(fpath, "db_storage/");
        if (rel) rel += strlen("db_storage/");
    }
    if (!rel || !*rel) {
        rel = strrchr(fpath, '/');
        rel = rel ? rel + 1 : fpath;
    }
    strncpy(g_db_names[g_db_count], rel, 255);
    g_db_names[g_db_count][255] = '\0';
    printf("  %s: salt=%s\n", g_db_names[g_db_count], salt);
    g_db_count++;
    return 0;
}

static int nftw_find_db_storage(const char *fpath, const struct stat *sb,
                                int typeflag, struct FTW *ftwbuf) {
    (void)sb; (void)ftwbuf;
    if (typeflag != FTW_D) return 0;

    const char *base = strrchr(fpath, '/');
    base = base ? base + 1 : fpath;
    if (strcmp(base, "db_storage") != 0)
        return 0;

    strncpy(g_current_db_dir, fpath, sizeof(g_current_db_dir) - 1);
    g_current_db_dir[sizeof(g_current_db_dir) - 1] = '\0';
    printf("Scanning db_storage: %s\n", g_current_db_dir);
    nftw(fpath, nftw_collect_db, 20, FTW_PHYS);
    return 0;
}

static int is_numeric_arg(const char *s) {
    if (!s || !*s) return 0;
    for (int i = 0; s[i]; i++)
        if (s[i] < '0' || s[i] > '9') return 0;
    return 1;
}

static int is_hex_char(unsigned char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static void lowercase_hex(char *hex);

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    for (size_t i = 0; i < out_len; i++) {
        int hi = hex_value((unsigned char)hex[i * 2]);
        int lo = hex_value((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

static int load_db_manifest(const char *manifest_path) {
    FILE *fp = fopen(manifest_path, "r");
    if (!fp) {
        fprintf(stderr, "Could not open DB manifest (%d): %s\n", errno, manifest_path);
        return 0;
    }

    printf("Loading DB manifest: %s\n", manifest_path);
    char line[10000];
    while (fgets(line, sizeof(line), fp) && g_db_count < MAX_DBS) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') continue;

        char *rel = strtok(line, "\t");
        char *salt = strtok(NULL, "\t");
        char *page_hex = strtok(NULL, "\t");
        if (!rel || !salt || !page_hex || strlen(salt) != 32 || strlen(page_hex) < DB_PAGE_SIZE * 2) {
            fprintf(stderr, "  SKIP manifest row (invalid): %s\n", rel ? rel : "(empty)");
            continue;
        }

        if (hex_to_bytes(page_hex, g_db_pages[g_db_count], DB_PAGE_SIZE) != 0) {
            fprintf(stderr, "  SKIP manifest row (bad page hex): %s\n", rel);
            continue;
        }

        strncpy(g_db_salts[g_db_count], salt, 32);
        g_db_salts[g_db_count][32] = '\0';
        lowercase_hex(g_db_salts[g_db_count]);
        strncpy(g_db_names[g_db_count], rel, 255);
        g_db_names[g_db_count][255] = '\0';
        printf("  %s: salt=%s\n", g_db_names[g_db_count], g_db_salts[g_db_count]);
        g_db_count++;
    }
    fclose(fp);
    return g_db_count;
}

static void lowercase_hex(char *hex) {
    for (int i = 0; hex[i]; i++)
        if (hex[i] >= 'A' && hex[i] <= 'F')
            hex[i] += 32;
}

static int verify_enc_key(const unsigned char *enc_key, const unsigned char *page1) {
    unsigned char mac_salt[SALT_SIZE];
    unsigned char mac_key[KEY_SIZE];
    unsigned char digest[CC_SHA512_DIGEST_LENGTH];
    uint32_t page_no = 1;

    for (int i = 0; i < SALT_SIZE; i++)
        mac_salt[i] = page1[i] ^ 0x3A;

    int kdf_status = CCKeyDerivationPBKDF(
        kCCPBKDF2,
        (const char *)enc_key,
        KEY_SIZE,
        mac_salt,
        SALT_SIZE,
        kCCPRFHmacAlgSHA512,
        2,
        mac_key,
        KEY_SIZE
    );
    if (kdf_status != kCCSuccess)
        return 0;

    CCHmacContext ctx;
    CCHmacInit(&ctx, kCCHmacAlgSHA512, mac_key, KEY_SIZE);
    CCHmacUpdate(&ctx, page1 + SALT_SIZE, DB_PAGE_SIZE - RESERVE_SIZE + IV_SIZE - SALT_SIZE);
    CCHmacUpdate(&ctx, &page_no, sizeof(page_no));
    CCHmacFinal(&ctx, digest);

    return memcmp(digest, page1 + DB_PAGE_SIZE - CC_SHA512_DIGEST_LENGTH, CC_SHA512_DIGEST_LENGTH) == 0;
}

static int add_verified_key(const char *key_hex_in, key_entry_t *keys, int *key_count) {
    char key_hex[65];
    unsigned char enc_key[KEY_SIZE];
    strncpy(key_hex, key_hex_in, 64);
    key_hex[64] = '\0';
    lowercase_hex(key_hex);

    if (hex_to_bytes(key_hex, enc_key, KEY_SIZE) != 0)
        return 0;

    int added = 0;
    for (int db_idx = 0; db_idx < g_db_count; db_idx++) {
        if (!verify_enc_key(enc_key, g_db_pages[db_idx]))
            continue;

        int dup = 0;
        for (int k = 0; k < *key_count; k++) {
            if (strcmp(keys[k].key_hex, key_hex) == 0 &&
                strcmp(keys[k].salt_hex, g_db_salts[db_idx]) == 0) {
                dup = 1;
                break;
            }
        }
        if (dup) continue;

        if (*key_count < MAX_KEYS) {
            strcpy(keys[*key_count].key_hex, key_hex);
            strcpy(keys[*key_count].salt_hex, g_db_salts[db_idx]);
            snprintf(keys[*key_count].full_pragma, sizeof(keys[*key_count].full_pragma),
                "x'%s%s'", key_hex, g_db_salts[db_idx]);
            (*key_count)++;
            added++;
            printf("\n  [FOUND] %s -> %s\n", key_hex, g_db_names[db_idx]);
        }
    }
    return added;
}

static int get_wechat_pids(pid_t *pids, int max) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t sz = 0;
    if (sysctl(mib, 4, NULL, &sz, NULL, 0) != 0 || sz == 0)
        return 0;

    struct kinfo_proc *procs = malloc(sz);
    if (!procs) return 0;

    if (sysctl(mib, 4, procs, &sz, NULL, 0) != 0) {
        free(procs);
        return 0;
    }

    int n = (int)(sz / sizeof(struct kinfo_proc));
    int count = 0;
    for (int i = 0; i < n && count < max; i++) {
        if (strstr(procs[i].kp_proc.p_comm, "WeChat")) {
            pids[count++] = procs[i].kp_proc.p_pid;
        }
    }
    free(procs);
    return count;
}

/* Read DB page 1 and return salt hex string */
static int read_db_page1(const char *path, char *salt_hex_out, unsigned char *page1_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fread(page1_out, 1, DB_PAGE_SIZE, f) != DB_PAGE_SIZE) { fclose(f); return -1; }
    fclose(f);
    /* Check if unencrypted */
    if (memcmp(page1_out, "SQLite format 3", 15) == 0) return -1;
    for (int i = 0; i < 16; i++)
        sprintf(salt_hex_out + i * 2, "%02x", page1_out[i]);
    salt_hex_out[32] = '\0';
    return 0;
}

static int scan_pid(pid_t pid, key_entry_t *keys, int *key_count) {
    printf("\nScanning PID: %d\n", pid);

    mach_port_t task;
    kern_return_t kr = task_for_pid(mach_task_self(), pid, &task);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "task_for_pid failed: %d\n", kr);
        fprintf(stderr, "Make sure: (1) running as root, (2) WeChat is ad-hoc signed\n");
        return 0;
    }
    printf("Got task port: %u\n", task);

    /* Scan memory for x' patterns */
    size_t total_scanned = 0;
    int region_count = 0;

    mach_vm_address_t addr = 0;
    while (1) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj_name;

        kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &info_count, &obj_name);
        if (kr != KERN_SUCCESS) break;
        if (size == 0) { addr++; continue; }  /* guard against infinite loop */

        if ((info.protection & (VM_PROT_READ | VM_PROT_WRITE)) ==
            (VM_PROT_READ | VM_PROT_WRITE)) {
            region_count++;

            mach_vm_address_t ca = addr;
            while (ca < addr + size) {
                mach_vm_size_t cs = addr + size - ca;
                if (cs > CHUNK_SIZE) cs = CHUNK_SIZE;

                vm_offset_t data;
                mach_msg_type_number_t dc;
                kr = mach_vm_read(task, ca, cs, &data, &dc);
                if (kr == KERN_SUCCESS) {
                    unsigned char *buf = (unsigned char *)data;
                    total_scanned += dc;

                    for (size_t i = 0; i + 64 < dc; i++) {
                        if (buf[i] == 'x' && buf[i + 1] == '\'') {
                            size_t run = 0;
                            while (i + 2 + run < dc && is_hex_char(buf[i + 2 + run]) && run < 256)
                                run++;
                            if (run >= 64 && i + 2 + run < dc && buf[i + 2 + run] == '\'') {
                                char key_hex[65];
                                memcpy(key_hex, buf + i + 2, 64);
                                key_hex[64] = '\0';
                                add_verified_key(key_hex, keys, key_count);
                                i += run + 2;
                            }
                        } else if (is_hex_char(buf[i])) {
                            size_t run = 0;
                            while (i + run < dc && is_hex_char(buf[i + run]) && run < 256)
                                run++;
                            if (run >= 64) {
                                char key_hex[65];
                                memcpy(key_hex, buf + i, 64);
                                key_hex[64] = '\0';
                                add_verified_key(key_hex, keys, key_count);
                                i += run - 1;
                            }
                        }
                    }

                    mach_vm_deallocate(mach_task_self(), data, dc);
                }
                if (cs > HEX_PATTERN_LEN + 3)
                    ca += cs - (HEX_PATTERN_LEN + 3);
                else
                    ca += cs;
            }
        }
        addr += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    printf("PID %d complete: %zuMB scanned, %d regions\n",
           pid, total_scanned / 1024 / 1024, region_count);
    return 1;
}

int main(int argc, char *argv[]) {
    printf("============================================================\n");
    printf("  macOS wemory Key Scanner (C version)\n");
    printf("============================================================\n");

    /* Resolve real user's HOME (sudo may change HOME to /var/root) */
    const char *home = getenv("HOME");
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user) {
        struct passwd *pw = getpwnam(sudo_user);
        if (pw && pw->pw_dir)
            home = pw->pw_dir;
    }
    if (!home) home = "/root";
    printf("User home: %s\n", home);

    const char *explicit_db_dir = NULL;
    pid_t explicit_pid = 0;
    if (argc >= 2) {
        if (is_numeric_arg(argv[1]))
            explicit_pid = atoi(argv[1]);
        else
            explicit_db_dir = argv[1];
    }
    if (argc >= 3 && is_numeric_arg(argv[2]))
        explicit_pid = atoi(argv[2]);

    /* Collect DB salts from a manifest or by recursively walking DB roots. */
    printf("\nScanning for DB files...\n");
    if (explicit_db_dir) {
        struct stat st;
        if (stat(explicit_db_dir, &st) == 0 && S_ISREG(st.st_mode)) {
            load_db_manifest(explicit_db_dir);
        } else if (stat(explicit_db_dir, &st) == 0 && S_ISDIR(st.st_mode)) {
            strncpy(g_current_db_dir, explicit_db_dir, sizeof(g_current_db_dir) - 1);
            g_current_db_dir[sizeof(g_current_db_dir) - 1] = '\0';
            printf("Scanning explicit DB root: %s\n", g_current_db_dir);
            /* Try nftw first, fall back to manual walk if it finds nothing */
            int nftw_ret = nftw(explicit_db_dir, nftw_collect_db, 20, FTW_PHYS);
            if (g_db_count == 0) {
                printf("nftw returned no DBs (ret=%d), trying manual walk...\n", nftw_ret);
                manual_collect_db_dir(explicit_db_dir);
            }
        } else {
            fprintf(stderr, "Explicit DB root path is invalid: %s\n", explicit_db_dir);
        }
    } else {
        const char *db_suffixes[] = {
            "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files",
            "Library/Containers/com.tencent.xinWeChat/Data",
            "Documents/xwechat_files",
            "Documents",
        };
        for (int root_idx = 0; root_idx < 4; root_idx++) {
            char db_base_dir[512];
            snprintf(db_base_dir, sizeof(db_base_dir), "%s/%s", home, db_suffixes[root_idx]);
            nftw(db_base_dir, nftw_find_db_storage, 20, FTW_PHYS);
        }
    }
    printf("Found %d encrypted DBs\n", g_db_count);

    if (g_db_count == 0) {
        fprintf(stderr, "No encrypted WeChat DBs found\n");
        return 1;
    }

    printf("\nScanning memory for keys...\n");
    key_entry_t keys[MAX_KEYS];
    int key_count = 0;

    int scanned_pids = 0;
    if (explicit_pid > 0) {
        if (explicit_pid <= 0) {
            fprintf(stderr, "Invalid PID\n");
            return 1;
        }
        scanned_pids += scan_pid(explicit_pid, keys, &key_count);
    } else {
        pid_t pids[64];
        int npids = get_wechat_pids(pids, 64);
        if (npids == 0) {
            fprintf(stderr, "WeChat not running or invalid PID\n");
            return 1;
        }
        printf("Found %d WeChat-related PIDs\n", npids);
        for (int i = 0; i < npids; i++) {
            scanned_pids += scan_pid(pids[i], keys, &key_count);
        }
    }

    if (scanned_pids == 0) {
        fprintf(stderr, "Could not read any WeChat process memory\n");
        return 1;
    }

    printf("\nScan complete: %d unique keys\n", key_count);

    /* Match keys to DBs */
    printf("\n%-25s %-66s %s\n", "Database", "Key", "Salt");
    printf("%-25s %-66s %s\n",
        "-------------------------",
        "------------------------------------------------------------------",
        "--------------------------------");

    int matched = 0;
    for (int i = 0; i < key_count; i++) {
        const char *db = NULL;
        for (int j = 0; j < g_db_count; j++) {
            if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                db = g_db_names[j];
                matched++;
                break;
            }
        }
        printf("%-25s %-66s %s\n",
            db ? db : "(unknown)",
            keys[i].key_hex,
            keys[i].salt_hex);
    }
    printf("\nMatched %d/%d keys to known DBs\n", matched, key_count);

    if (matched == 0) {
        unlink("all_keys.json");
        fprintf(stderr, "No keys matched known DBs\n");
        return 2;
    }

    /* Save JSON: { "rel/path.db": { "enc_key": "hex" }, ... }
     * Uses forward slashes (native macOS paths, valid JSON without escaping).
     */
    const char *out_path = "all_keys.json";
    FILE *fp = fopen(out_path, "w");
    if (fp) {
        fprintf(fp, "{\n");
        int first = 1;
        for (int i = 0; i < key_count; i++) {
            const char *db = NULL;
            for (int j = 0; j < g_db_count; j++) {
                if (strcmp(keys[i].salt_hex, g_db_salts[j]) == 0) {
                    db = g_db_names[j];
                    break;
                }
            }
            if (!db) continue;
            fprintf(fp, "%s  \"%s\": {\"enc_key\": \"%s\"}",
                first ? "" : ",\n", db, keys[i].key_hex);
            first = 0;
        }
        fprintf(fp, "\n}\n");
        fclose(fp);
        printf("Saved to %s\n", out_path);
    }

    return 0;
}
