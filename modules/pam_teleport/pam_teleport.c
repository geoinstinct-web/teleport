#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
  #include <security/pam_appl.h>
  #include <security/pam_modules.h>
#else
  #include <security/pam_appl.h>
  #include <security/pam_modules.h>
  #include <security/pam_ext.h>
  #include <sys/types.h>
#endif

int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (argc > 0 && argv[0][0] == '0') {
        return PAM_ACCT_EXPIRED;
    }

    pam_info(pamh, "Account opened successfully.");
    return PAM_SUCCESS;
}

int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    int pam_err;

    // If the "echo_ruser" command is requested that will echo out the value of
    // the PAM_RUSER variable.
    if (argc > 0 && strcmp(argv[0], "echo_ruser") == 0) {
	    const char **ruser;

        pam_err = pam_get_item(pamh, PAM_RUSER, (const void **)ruser);
        if (pam_err < 0) {
            return PAM_SYSTEM_ERR;
        }

        pam_info(pamh, "%s", *ruser);
        return PAM_SUCCESS;
    }

    // If the "set_env" command is requested, set the PAM environment variable.
    if (argc > 0 && strcmp(argv[0], "set_env") == 0) {
        pam_err = pam_putenv(pamh, argv[1]);
        if (pam_err < 0) {
            return PAM_SYSTEM_ERR;
        }
        return PAM_SUCCESS;
    }

    if (argc > 0 && argv[0][0] == '0') {
        return PAM_SESSION_ERR;
    }

    pam_info(pamh, "Session open successfully.");
    return PAM_SUCCESS;
}

int pam_sm_close_session (pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    if (argc > 0 && argv[0][0] == '0') {
        return PAM_SESSION_ERR;
    }

    pam_info(pamh, "Session closed successfully.");
    return PAM_SUCCESS;
}
