#ifndef ATTACK_JAMMER_H
#define ATTACK_JAMMER_H

#include <stdint.h>
#include <stdbool.h>

void jammer_wifi_start(void);
void jammer_bt_start(void);
void jammer_stop(void);
bool jammer_wifi_is_running(void);
bool jammer_bt_is_running(void);
uint64_t jammer_get_packets(void);

#endif