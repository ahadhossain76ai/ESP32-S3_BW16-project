#ifndef ATTACK_DUCKY_H
#define ATTACK_DUCKY_H

#include <stdbool.h>

int ducky_inject(const char *script);
void ducky_stop(void);
bool ducky_is_running(void);

#endif