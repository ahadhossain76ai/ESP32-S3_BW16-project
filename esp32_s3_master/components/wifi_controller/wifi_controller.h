#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

#include "esp_wifi.h"
#include <stdint.h>
#include <stdbool.h>

#define MAX_ATTACK_TARGETS 10

// AP functions
void wifictl_ap_start(wifi_config_t *wifi_config);
void wifictl_ap_stop(void);

// STA functions
void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]);
bool wifictl_sta_connect_home(const char *ssid, const char *pass);
bool wifictl_sta_is_connected(void);
void wifictl_sta_disconnect(void);
void wifictl_set_scan_done_handler(esp_event_handler_t handler);

// Auto-connect on boot
void wifictl_auto_connect_saved(void);

// MAC functions
void wifictl_set_ap_mac(const uint8_t *mac_ap);
void wifictl_get_ap_mac(uint8_t *mac_ap);
void wifictl_restore_ap_mac(void);
void wifictl_get_sta_mac(uint8_t *mac_sta);

// Channel
void wifictl_set_channel(uint8_t channel);

// Management AP
void wifictl_get_mgmt_creds(char* ssid, char* pass);
void wifictl_get_sta_creds(char* ssid, char* pass);
void wifictl_mgmt_ap_start(void);
void wifictl_mgmt_ap_stop(void);

#endif
