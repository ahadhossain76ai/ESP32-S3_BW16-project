#ifndef ATTACK_EVILTWIN_H
#define ATTACK_EVILTWIN_H

#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Start Evil Twin attack
 * @param target_ssid Real SSID to clone
 * @param evil_ssid Clone SSID name (NULL = use target_ssid)
 * @param target_bssid BSSID of target AP
 * @param channel Channel of target AP
 * @param is_5ghz Whether target is on 5GHz
 * @param phishing_page Path to DevilTwin HTML page in SPIFFS (e.g. "DevilTwin/EvilTwin_tp_link.html"), NULL = default
 */
void eviltwin_start(const char *target_ssid, const char *evil_ssid,
                    const uint8_t *target_bssid, uint8_t channel, 
                    bool is_5ghz, const char *phishing_page);

void eviltwin_stop(void);
void eviltwin_cleanup(void);
bool eviltwin_is_running(void);

// Captured password access
int captured_data_get_count(void);
const char* captured_data_get(int index, char *ssid, char *password, char *time_str);
bool captured_data_is_verified(int index);
void captured_data_clear(void);
void start_captive_portal(const uint8_t *bssid);

#endif
