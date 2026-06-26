#ifndef WIFI_PASS_VERIFIER_H
#define WIFI_PASS_VERIFIER_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_netif.h"

typedef enum {
    WIFI_VERIFY_CORRECT = 0,
    WIFI_VERIFY_WRONG_PASSWORD = 1,
    WIFI_VERIFY_AP_NOT_FOUND = 2,
    WIFI_VERIFY_TIMEOUT = 3,
    WIFI_VERIFY_ERROR = 4,
} wifi_verify_status_t;

typedef struct {
    wifi_verify_status_t status;
    esp_ip4_addr_t ip;
    esp_ip4_addr_t gateway;
    esp_ip4_addr_t netmask;
    uint8_t disconnect_reason;
    char ssid[33];
} wifi_verify_result_t;

void wifi_verify_init(void);
wifi_verify_result_t wifi_verify_password(const char *ssid, const char *password, const uint8_t *bssid, uint32_t timeout_ms);
const char *wifi_verify_status_str(wifi_verify_status_t status);

#endif
