#ifndef PACKET_INJECTION_H
#define PACKET_INJECTION_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Frame injection functions
int wifi_tx_deauth_frame(uint8_t bssid[6], uint8_t *client_mac, uint16_t reason);
int wifi_tx_beacon_frame(uint8_t bssid[6], uint8_t *ssid, int ssid_len, uint8_t channel);
int wifi_tx_disassoc_frame(uint8_t bssid[6], uint8_t *client_mac, uint16_t reason);
int wifi_tx_probe_req(uint8_t *bssid, uint8_t *ssid, int ssid_len);

// 5GHz specific
int wifi_set_channel_5ghz(uint8_t channel);
int wifi_send_raw_frame_5ghz(uint8_t *frame, int len);

// Repeater functions
int repeater_start(const char *ssid, const char *password);
int repeater_stop(void);
bool repeater_is_active(void);

#ifdef __cplusplus
}
#endif

#endif
