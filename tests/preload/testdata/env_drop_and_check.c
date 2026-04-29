/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 *
 * Test fixture for the systrap-supervised env-preservation path.
 *
 * Invoked twice:
 *   parent:  env_drop_and_check <self_path>
 *   child:   env_drop_and_check <self_path> child   (via execve with NULL env)
 *
 * The parent re-execs itself with `argv[1]="child"` and `envp = {NULL}`,
 * simulating chromium's sandbox launcher / sudo / custom CI runners
 * that rebuild envp from scratch and drop the parent's env.
 *
 * The child reads /proc/self/environ, counts UWGS_* vars and checks
 * for LD_PRELOAD. Without the supervisor's preserveUWGSEnvAtExecve
 * fix, both counts are 0 and the child exits 2. With the fix in
 * place (env injected before kernel processes the execve), both are
 * non-zero and the child exits 0 after printing UWGS_COUNT/LD_PRELOAD
 * to stdout for the test to assert on.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void child_check(void) {
    int fd = open("/proc/self/environ", O_RDONLY);
    if (fd < 0) {
        perror("open /proc/self/environ");
        exit(1);
    }
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n < 0) {
        perror("read /proc/self/environ");
        exit(1);
    }
    buf[n] = 0;
    int uwgs_count = 0;
    int has_ld_preload = 0;
    char *p = buf;
    char *end = buf + n;
    while (p < end) {
        size_t len = strlen(p);
        if (len == 0) break;
        if (strncmp(p, "UWGS_", 5) == 0) uwgs_count++;
        if (strncmp(p, "LD_PRELOAD=", 11) == 0) has_ld_preload = 1;
        p += len + 1;
    }
    printf("UWGS_COUNT=%d LD_PRELOAD=%d\n", uwgs_count, has_ld_preload);
    if (uwgs_count == 0) {
        fprintf(stderr, "FAIL: no UWGS_* env vars survived; supervisor env-injection didn't run\n");
        exit(2);
    }
    exit(0);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[2], "child") == 0) {
        child_check();
        return 0;
    }
    if (argc != 2) {
        fprintf(stderr, "usage: %s <self_path>\n", argv[0]);
        return 64;
    }
    /* Re-exec self with empty env. Supervisor MUST inject UWGS_* /
     * LD_PRELOAD before the kernel processes the execve. */
    char *new_argv[] = {argv[1], (char *)"child", NULL};
    char *empty_env[] = {NULL};
    execve(argv[1], new_argv, empty_env);
    perror("execve self with empty env");
    return 1;
}
