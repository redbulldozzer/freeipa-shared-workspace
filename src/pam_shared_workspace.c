/* Pilot for Linux-PAM/LightDM. Does not store passwords or create Kerberos tickets.
 * Keep /etc/pam.d/common-* unchanged. Install only after standalone PAM tests.
 */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <security/pam_appl.h>
#include <security/pam_ext.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CONF "/etc/shared-workspace.conf"
#define RUN "/run/shared-workspace"
#define STATE_DIR "/var/lib/shared-workspace"
#define RECENT STATE_DIR "/recent-users"
#define KEY "shared-workspace-state"
#define NAME_SIZE 128

struct config { char target[NAME_SIZE]; char group[NAME_SIZE]; };
struct state { char employee[NAME_SIZE]; char shift[33]; int lock_fd; int opened; };

static int valid_name(const char *s) {
    if (!s || !*s || strlen(s) >= NAME_SIZE) return 0;
    for (; *s; ++s)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= '0' && *s <= '9') ||
              *s == '-' || *s == '_' || *s == '.' || *s == '@')) return 0;
    return 1;
}

static int local_user(const char *name) {
    FILE *f = fopen("/etc/passwd", "re");
    if (!f) return 0;
    struct passwd *p; int found = 0;
    while ((p = fgetpwent(f))) if (!strcmp(p->pw_name, name)) { found = 1; break; }
    fclose(f); return found;
}

static FILE *trusted_read(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        (st.st_mode & 0022)) { close(fd); return NULL; }
    FILE *f = fdopen(fd, "r");
    if (!f) close(fd);
    return f;
}

static int get_config(struct config *c) {
    memset(c, 0, sizeof(*c));
    FILE *f = trusted_read(CONF);
    if (!f) return -1;
    char line[256]; int bad = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!*line || *line == '#') continue;
        if (!strncmp(line, "target=", 7) && valid_name(line + 7) && !*c->target)
            strcpy(c->target, line + 7);
        else if (!strncmp(line, "group=", 6) && valid_name(line + 6) && !*c->group)
            strcpy(c->group, line + 6);
        else bad = 1;
    }
    if (ferror(f)) bad = 1;
    fclose(f);
    if (bad || !*c->target || !*c->group || !local_user(c->target)) return -1;
    struct passwd *p = getpwnam(c->target);
    if (!p || p->pw_uid < 1000) return -1;
    return 0;
}

static int allowed(const struct config *c, const char *name) {
    if (!valid_name(name) || local_user(name)) return 0;
    struct passwd *p = getpwnam(name);
    struct group *wanted = getgrnam(c->group);
    if (!p || !wanted) return 0;
    int count = 0;
    (void)getgrouplist(name, p->pw_gid, NULL, &count);
    if (count <= 0 || count > 4096) return 0;
    gid_t *groups = calloc((size_t)count, sizeof(*groups));
    if (!groups) return 0;
    int actual = count, found = 0;
    if (getgrouplist(name, p->pw_gid, groups, &actual) >= 0)
        for (int i = 0; i < actual; i++) if (groups[i] == wanted->gr_gid) { found = 1; break; }
    free(groups);
    return found;
}

static int ensure_dir(const char *path, mode_t mode) {
    if (mkdir(path, mode) && errno != EEXIST) return -1;
    struct stat st;
    if (lstat(path, &st) || !S_ISDIR(st.st_mode) || st.st_uid || (st.st_mode & 0022)) return -1;
    return chmod(path, mode);
}

static int add_recent(const char *name) {
    if (geteuid() || !valid_name(name) || ensure_dir(STATE_DIR, 0755)) return -1;
    int lock = open(STATE_DIR "/recent.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (lock < 0 || fchmod(lock, 0600) || flock(lock, LOCK_EX)) { if (lock >= 0) close(lock); return -1; }
    char names[12][NAME_SIZE]; int count = 0;
    FILE *in = trusted_read(RECENT);
    char line[NAME_SIZE + 2];
    if (in) {
        while (count < 12 && fgets(line, sizeof(line), in)) {
            line[strcspn(line, "\r\n")] = 0;
            if (valid_name(line) && strcmp(line, name)) strcpy(names[count++], line);
        }
        fclose(in);
    }
    char temp[256]; snprintf(temp, sizeof(temp), STATE_DIR "/.recent-%ld", (long)getpid());
    int fd = open(temp, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) { close(lock); return -1; }
    int ok = fchmod(fd, 0644) == 0 && dprintf(fd, "%s\n", name) > 0;
    for (int i = 0; ok && i < count && i < 11; i++) if (dprintf(fd, "%s\n", names[i]) <= 0) ok = 0;
    if (fsync(fd)) ok = 0;
    if (close(fd)) ok = 0;
    if (!ok || rename(temp, RECENT)) { unlink(temp); close(lock); return -1; }
    close(lock); return 0;
}

static void cleanup(pam_handle_t *pamh, void *data, int error) {
    (void)pamh; (void)error;
    struct state *s = data;
    if (s) { if (s->lock_fd >= 0) close(s->lock_fd); free(s); }
}

static const char *service(pam_handle_t *pamh) {
    const void *v = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, &v) != PAM_SUCCESS || !v) return "";
    return v;
}

static int is_login(pam_handle_t *pamh) {
    const char *name = service(pamh);
    return !strcmp(name, "lightdm") || !strcmp(name, "shared-workspace-login") ||
           !strcmp(name, "shared-workspace-check");
}

static int keyring_token(pam_handle_t *pamh) {
    /* A random machine-local key, not an employee/domain password. The host
     * filesystem must be encrypted. This is available only to root at login. */
    int fd = open("/etc/shared-workspace.keyring", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return PAM_SYSTEM_ERR;
    struct stat st; char token[65] = {0};
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0077) || st.st_size != 64) {
        close(fd); return PAM_SYSTEM_ERR;
    }
    ssize_t n = read(fd, token, 64);
    close(fd);
    int r = n == 64 ? pam_set_item(pamh, PAM_AUTHTOK, token) : PAM_SYSTEM_ERR;
    explicit_bzero(token, sizeof(token));
    return r;
}

static int domain_auth(pam_handle_t *outer, const char *employee, int flags) {
    const void *conv = NULL;
    if (pam_get_item(outer, PAM_CONV, &conv) != PAM_SUCCESS || !conv) return PAM_SYSTEM_ERR;
    pam_handle_t *inner = NULL;
    int r = pam_start("shared-workspace-domain", employee, conv, &inner);
    if (r != PAM_SUCCESS) return r;
    const int items[] = { PAM_TTY, PAM_RHOST };
    for (unsigned i = 0; i < sizeof(items) / sizeof(items[0]); i++) {
        const void *v = NULL;
        if (pam_get_item(outer, items[i], &v) == PAM_SUCCESS && v)
            pam_set_item(inner, items[i], v);
    }
    r = pam_authenticate(inner, flags & PAM_SILENT);
    if (r == PAM_SUCCESS) r = pam_acct_mgmt(inner, 0);
    /* Expired passwords require a normal password-change flow, not remapping. */
    if (r != PAM_SUCCESS) pam_syslog(outer, LOG_NOTICE, "domain authentication/account rejected for %s (%d)", employee, r);
    pam_end(inner, r);
    return r;
}

static int current_identity(char *employee, char *shift) {
    FILE *f = trusted_read(RUN "/current");
    if (!f) return -1;
    char line[256]; int user_ok = 0, shift_ok = 0;
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (!strncmp(line, "employee=", 9) && valid_name(line + 9)) {
            strcpy(employee, line + 9); user_ok = 1;
        } else if (!strncmp(line, "shift=", 6) && strlen(line + 6) == 32) {
            strcpy(shift, line + 6); shift_ok = 1;
        }
    }
    fclose(f);
    if (!user_ok || !shift_ok) return -1;
    /* A stale current file without a live session lock is never an identity. */
    int fd = open(RUN "/session.lock", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0022)) {
        close(fd); return -1;
    }
    int rc = flock(fd, LOCK_SH | LOCK_NB), saved = errno;
    close(fd);
    return rc < 0 && saved == EWOULDBLOCK ? 0 : -1;
}

static int write_current(const char *employee, const char *shift) {
    if (geteuid() || ensure_dir(RUN, 0755)) return -1;
    char path[256]; snprintf(path, sizeof(path), RUN "/.current-%s", shift);
    int out = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (out < 0) return -1;
    int ok = fchmod(out, 0644) == 0;
    if (dprintf(out, "employee=%s\nshift=%s\npid=%ld\n", employee, shift, (long)getpid()) <= 0) ok = 0;
    if (fsync(out)) ok = 0;
    if (close(out)) ok = 0;
    if (!ok || rename(path, RUN "/current")) { unlink(path); return -1; }
    return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)argc; (void)argv;
    const char *user = NULL;
    int r = pam_get_user(pamh, &user, NULL);
    if (r != PAM_SUCCESS || !user) return PAM_USER_UNKNOWN;
    struct config c;
    if (get_config(&c)) return local_user(user) ? PAM_IGNORE : PAM_AUTH_ERR;
    if (!strcmp(user, c.target)) {
        if (strcmp(service(pamh), "cinnamon-screensaver") &&
            strcmp(service(pamh), "shared-workspace-unlock-check")) return PAM_AUTH_ERR;
        char employee[NAME_SIZE], shift[33];
        if (current_identity(employee, shift) || !allowed(&c, employee)) return PAM_AUTH_ERR;
        pam_info(pamh, "Domain password for %s", employee);
        return domain_auth(pamh, employee, flags);
    }
    /* Preserve normal authentication for existing local recovery accounts. */
    if (local_user(user)) return PAM_IGNORE;
    if (!is_login(pamh) || !allowed(&c, user) || geteuid() != 0) return PAM_AUTH_ERR;
    struct state *s = calloc(1, sizeof(*s));
    if (!s) return PAM_BUF_ERR;
    s->lock_fd = -1;
    strcpy(s->employee, user);
    unsigned char random[16];
    if (getrandom(random, sizeof(random), 0) != sizeof(random)) { free(s); return PAM_SYSTEM_ERR; }
    for (int i = 0; i < 16; i++) snprintf(s->shift + i * 2, 3, "%02x", random[i]);
    r = domain_auth(pamh, s->employee, flags);
    if (r != PAM_SUCCESS) { free(s); return r; }
    if (add_recent(s->employee)) pam_syslog(pamh, LOG_WARNING, "could not update recent users for %s", s->employee);
    char old_employee[NAME_SIZE], old_shift[33];
    if (!current_identity(old_employee, old_shift) && strcmp(old_employee, s->employee)) {
        if (write_current(s->employee, s->shift)) { free(s); return PAM_SYSTEM_ERR; }
        pam_syslog(pamh, LOG_NOTICE, "shift-end employee=%s shift=%s reason=takeover", old_employee, old_shift);
        pam_syslog(pamh, LOG_NOTICE, "shift-start employee=%s shift=%s workspace=%s reason=takeover", s->employee, s->shift, c.target);
    }
    r = pam_set_data(pamh, KEY, s, cleanup);
    if (r != PAM_SUCCESS) { free(s); return r; }
    r = pam_set_item(pamh, PAM_USER, c.target);
    if (r != PAM_SUCCESS) return r;
    char env[256];
    snprintf(env, sizeof(env), "SHARED_WORKSPACE_EMPLOYEE=%s", s->employee);
    if (pam_putenv(pamh, env) != PAM_SUCCESS) return PAM_SYSTEM_ERR;
    snprintf(env, sizeof(env), "SHARED_WORKSPACE_SHIFT=%s", s->shift);
    if (pam_putenv(pamh, env) != PAM_SUCCESS) return PAM_SYSTEM_ERR;
    return keyring_token(pamh);
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const char *user = NULL; struct config c;
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) return PAM_SESSION_ERR;
    if (get_config(&c)) return local_user(user) ? PAM_IGNORE : PAM_SESSION_ERR;
    if (strcmp(user, c.target)) return PAM_IGNORE;
    const void *data = NULL;
    if (geteuid() || !is_login(pamh) || pam_get_data(pamh, KEY, &data) != PAM_SUCCESS || !data)
        return PAM_SESSION_ERR;
    struct state *s = (struct state *)data;
    if (s->opened) return PAM_SESSION_ERR;
    if (ensure_dir(RUN, 0755)) return PAM_SESSION_ERR;
    struct stat st;
    int fd = open(RUN "/session.lock", O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0644);
    if (fd < 0) return PAM_SESSION_ERR;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid || (st.st_mode & 0022) || fchmod(fd, 0644) || flock(fd, LOCK_EX | LOCK_NB)) {
        close(fd); pam_error(pamh, "Shared workspace is already in use. End the previous session first.");
        return PAM_SESSION_ERR;
    }
    if (write_current(s->employee, s->shift)) { close(fd); return PAM_SESSION_ERR; }
    s->lock_fd = fd; s->opened = 1;
    pam_syslog(pamh, LOG_NOTICE, "shift-start employee=%s shift=%s workspace=%s", s->employee, s->shift, c.target);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    (void)flags; (void)argc; (void)argv;
    const void *data = NULL;
    if (pam_get_data(pamh, KEY, &data) != PAM_SUCCESS || !data) return PAM_IGNORE;
    struct state *s = (struct state *)data;
    if (s->opened) {
        if (geteuid()) return PAM_SESSION_ERR;
        char employee[NAME_SIZE], shift[33];
        if (!current_identity(employee, shift))
            pam_syslog(pamh, LOG_NOTICE, "shift-end employee=%s shift=%s", employee, shift);
        else
            pam_syslog(pamh, LOG_NOTICE, "shift-end employee=%s shift=%s", s->employee, s->shift);
        unlink(RUN "/current");
        close(s->lock_fd); s->lock_fd = -1; s->opened = 0;
    }
    return PAM_SUCCESS;
}
