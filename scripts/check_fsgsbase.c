#define _GNU_SOURCE
#include <stdio.h>
#include <signal.h>
#include <assert.h>
#include <string.h>
#include <ucontext.h>
#include <setjmp.h>
#include <stdlib.h>
#include <errno.h>

#define RC 0xffff
static jmp_buf env_buf;

static void handle_sigill(int num) {
    assert(num == SIGILL);

    longjmp(env_buf, RC);
}

int check_fsgsbase_enablement(void) {
    int gs_read_data = 0;
    int gs_write_data = 0x0f;
    int __seg_gs *offset_ptr = 0;   // offset relative to GS. support since gcc-6

    sighandler_t handler_orig = signal(SIGILL, handle_sigill);
    if (handler_orig == SIG_ERR) {
        fprintf(stderr, "registering signal handler failed, errno = %d", errno);
        return -1;
    }

    int ret = setjmp(env_buf);
    if (ret == RC) {
        // return from SIGILL handler
        fprintf(stderr, "\tSIGILL Caught !\n");
        return -1;
    }
    if (ret != 0) {
        fprintf(stderr, "setjmp failed");
        return -1;
    }

    // Check if kernel supports FSGSBASE
    asm("rdgsbase %0" :: "r" (&gs_read_data));
    asm("wrgsbase %0" :: "r" (&gs_write_data));

    if (*offset_ptr != 0x0f) {
        fprintf(stderr, "GS register data not match\n");
        return -1;
    };

    // Restore the GS register and original signal handler
    asm("wrgsbase %0" :: "r" (&gs_read_data));
    handler_orig = signal(SIGILL, handler_orig);
    if (handler_orig == SIG_ERR) {
        fprintf(stderr, "restoring default signal handler failed, errno = %d", errno);
        return -1;
    }

    return 0;
}

int main() {
    int ret;

    if ((ret = check_fsgsbase_enablement()) == 0) {
        printf("[Check fsgsbase]: PASS\n");
    } else {
        printf("[Check fsgsbase]: FAILED\n");
    }

    return ret;
}
