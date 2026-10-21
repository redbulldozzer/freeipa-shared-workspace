#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int converse(int count, const struct pam_message **messages,
                    struct pam_response **out, void *unused) {
    (void)unused;
    struct pam_response *replies = calloc((size_t)count, sizeof(*replies));
    if (!replies) return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        const struct pam_message *m = messages[i];
        if (m->msg_style == PAM_PROMPT_ECHO_OFF) {
            char *password = getpass(m->msg);
            if (!password) goto fail;
            replies[i].resp = strdup(password);
            explicit_bzero(password, strlen(password));
            if (!replies[i].resp) goto fail;
        } else if (m->msg_style == PAM_TEXT_INFO || m->msg_style == PAM_ERROR_MSG) {
            fprintf(stderr, "%s\n", m->msg);
        } else goto fail;
    }
    *out = replies;
    return PAM_SUCCESS;
fail:
    for (int i = 0; i < count; i++) {
        if (replies[i].resp) {
            explicit_bzero(replies[i].resp, strlen(replies[i].resp));
            free(replies[i].resp);
        }
    }
    free(replies); return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: pam-probe SERVICE USER [session]\n"); return 2;
    }
    struct pam_conv conv = {converse, NULL};
    pam_handle_t *pamh = NULL;
    int r = pam_start(argv[1], argv[2], &conv, &pamh);
    if (r != PAM_SUCCESS) return 2;
    r = pam_authenticate(pamh, 0);
    printf("authenticate=%d (%s)\n", r, pam_strerror(pamh, r));
    if (r == PAM_SUCCESS) {
        const void *user = NULL;
        pam_get_item(pamh, PAM_USER, &user);
        printf("mapped_user=%s\n", (const char *)user);
        const char *employee = pam_getenv(pamh, "SHARED_WORKSPACE_EMPLOYEE");
        printf("employee=%s\n", employee ? employee : "(none)");
        r = pam_acct_mgmt(pamh, 0);
        printf("account=%d (%s)\n", r, pam_strerror(pamh, r));
    }
    if (r == PAM_SUCCESS && argc == 4 && !strcmp(argv[3], "session")) {
        r = pam_setcred(pamh, PAM_ESTABLISH_CRED);
        printf("setcred=%d\n", r);
        if (r == PAM_SUCCESS) {
            r = pam_open_session(pamh, 0);
            printf("open_session=%d (%s)\n", r, pam_strerror(pamh, r));
            if (r == PAM_SUCCESS) {
                puts("Session held. Press Enter to close."); fflush(stdout);
                (void)getchar();
                r = pam_close_session(pamh, 0);
                printf("close_session=%d\n", r);
            }
            pam_setcred(pamh, PAM_DELETE_CRED);
        }
    }
    pam_end(pamh, r);
    return r == PAM_SUCCESS ? 0 : 1;
}
