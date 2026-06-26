#ifndef ATTACK_METHODS_H
#define ATTACK_METHODS_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_wifi.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// ==================== 5GHz CHANNEL LIST ====================
#define NUM_5GHZ_CHANNELS 25
extern const uint8_t g_5ghz_channels_list[NUM_5GHZ_CHANNELS];

// ==================== BEACON SPAM ====================
void attack_method_beacon_spam(const wifi_ap_record_t *ap, int count);

// ==================== DEAUTH FLOOD ====================
void attack_method_deauth_flood(const wifi_ap_record_t *ap, int count);
void attack_method_deauth_stop(void);

// ==================== ROGUE AP ====================
void attack_method_rogueap(const wifi_ap_record_t *ap);
void attack_method_rogueap_stop(void);

// ==================== BROADCAST DEAUTH ====================
void attack_method_broadcast(const wifi_ap_record_t *ap, int count);
void attack_method_broadcast_stop(void);

// ==================== RTS FLOOD ====================
void attack_method_rts_flood(const wifi_ap_record_t *ap, int count);

// ==================== PROBE RESPONSE FLOOD ====================
void attack_method_probe_flood(const wifi_ap_record_t *ap, int count);

// ==================== PMKID CAPTURE ====================
void attack_method_pmkid_capture(const wifi_ap_record_t *ap);

// ==================== EVIL TWIN ====================
int attack_method_eviltwin(const wifi_ap_record_t *ap, const char *phishing_page);

// ==================== JAMMER ====================
void attack_method_jammer_start(void);
void attack_method_jammer_stop(void);

// ==================== BLUETOOTH JAMMER ====================
void attack_method_bt_jammer_start(void);
void attack_method_bt_jammer_stop(void);

// ==================== WIFI DUCKY ====================
int attack_method_ducky_inject(const char *script);
void attack_method_ducky_stop(void);

// ==================== BW16 5GHz METHODS ====================
bool attack_method_bw16_scan_5ghz(void);
bool attack_method_bw16_deauth_5ghz(uint8_t channel, const uint8_t *bssid);

// ==================== STOP ALL ====================
void attack_method_stop_all(void);

#ifdef __cplusplus
}
#endif

#endif // ATTACK_METHODS_H
