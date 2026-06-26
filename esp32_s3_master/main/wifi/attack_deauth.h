#ifndef ATTACK_DEAUTH_H
#define ATTACK_DEAUTH_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
    bool is_5ghz;        // true = 5GHz (via BW16), false = 2.4GHz (native)
    char ssid[33];       // For reference
} deauth_target_t;

void deauth_start(deauth_target_t *targets, int count, uint8_t *client_mac);
void deauth_stop(void);
bool deauth_is_running(void);
uint64_t deauth_get_packets_sent(void);

#endif
