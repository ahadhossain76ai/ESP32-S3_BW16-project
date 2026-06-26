#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi_types.h"

#define MAX_PMKID_CAPTURES 50
#define PMKID_LENGTH 16
#define BSSID_LENGTH 6

typedef struct {
    uint8_t bssid[BSSID_LENGTH];
    uint8_t pmkid[PMKID_LENGTH];
    uint8_t ap_mac[BSSID_LENGTH];
    uint8_t sta_mac[BSSID_LENGTH];
    int8_t rssi;
    uint32_t timestamp_ms;
    char ssid[33];
    bool verified;
} pmkid_capture_t;

/**
 * @brief Initialize PMKID capture system
 * Registers promiscuous callback for management frames
 */
void pmkid_capture_init(void);

/**
 * @brief Start PMKID capture on specific channel
 * @param channel Target channel (1-13 for 2.4GHz, 36-165 for 5GHz via BW16)
 * @param is_5ghz Whether to use BW16 for 5GHz channels
 */
void pmkid_capture_start(uint8_t channel, bool is_5ghz);

/**
 * @brief Stop PMKID capture
 */
void pmkid_capture_stop(void);

/**
 * @brief Start auto-scanning all channels for PMKID
 * Cycles through channels 1-13 (2.4GHz) and sends deauth to provoke handshake
 */
void pmkid_capture_auto_scan(void);

/**
 * @brief Get number of captured PMKIDs
 */
int pmkid_capture_get_count(void);

/**
 * @brief Get captured PMKID by index
 */
const pmkid_capture_t* pmkid_capture_get(int index);

/**
 * @brief Clear all captured PMKIDs
 */
void pmkid_capture_clear(void);

/**
 * @brief Export captured PMKIDs as JSON string (for Web UI)
 * Caller must free the returned string
 */
char* pmkid_capture_export_json(void);

/**
 * @brief Check if PMKID capture is currently running
 */
bool pmkid_capture_is_running(void);

/**
 * @brief Get total packets analyzed
 */
uint32_t pmkid_capture_get_packet_count(void);

#endif // ATTACK_PMKID_H
