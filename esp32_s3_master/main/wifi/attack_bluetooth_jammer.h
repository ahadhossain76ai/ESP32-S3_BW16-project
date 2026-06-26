#ifndef ATTACK_BLUETOOTH_JAMMER_H
#define ATTACK_BLUETOOTH_JAMMER_H

#include <stdbool.h>
#include <stdint.h>

void bt_jammer_start(void);
void bt_jammer_stop(void);
bool bt_jammer_is_running(void);
uint64_t bt_jammer_get_packets(void);

#endif
