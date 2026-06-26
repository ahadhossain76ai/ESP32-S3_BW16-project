#ifndef ATTACK_BEACON_SPAM_H
#define ATTACK_BEACON_SPAM_H

#include <stdbool.h>

/**
 * @brief Start beacon spam attack
 * @param ssids Array of SSID strings
 * @param quantities Array of quantities per SSID
 * @param fishing_pages Array of fishing page paths (e.g. "Fishing_Web/tp_link.html"), NULL = no fishing
 * @param count Number of SSID entries
 */
void beacon_spam_start(const char **ssids, int *quantities, const char **fishing_pages, int count);
void beacon_spam_stop(void);
bool beacon_spam_is_running(void);

#endif
