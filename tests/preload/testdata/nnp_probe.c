/*
 * Copyright (c) 2026 Reindert Pelsma
 * SPDX-License-Identifier: ISC
 */

#include <stdio.h>
#include <sys/prctl.h>

int main(void) {
  int value = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  if (value < 0)
    return 1;
  printf("%d", value);
  return 0;
}
