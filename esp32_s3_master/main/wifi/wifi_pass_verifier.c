#include "wifi_pass_verifier.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include <string.h>

static const char *TAG = "wifi_verify";
#define EV_GOT_IP       BIT0
#define EV_WRONG_PASS   BIT1
#define EV_AP_NOT_FOUND BIT2
#define EV_OTHER_DISC   BIT3

static bool s_init_done = false;
static EventGroupHandle_t s_ev_group = NULL;
static volatile bool s_expecting = false;
static volatile uint8_t s_disc_reason = 0;

static void wifi_verify_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (!s_expecting) return;
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)data;
        s_disc_reason = disc->reason;
        if (disc->reason == WIFI_REASON_NO_AP_FOUND)
            xEventGroupSetBits(s_ev_group, EV_AP_NOT_FOUND);
        else if (disc->reason == WIFI_REASON_AUTH_FAIL || 
                 disc->reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT ||
                 disc->reason == WIFI_REASON_HANDSHAKE_TIMEOUT)
            xEventGroupSetBits(s_ev_group, EV_WRONG_PASS);
        else
            xEventGroupSetBits(s_ev_group, EV_OTHER_DISC);
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        xEventGroupSetBits(s_ev_group, EV_GOT_IP);
    }
}

void wifi_verify_init(void) {
    if (s_init_done) return;
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, wifi_verify_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, wifi_verify_event_handler, NULL));
    s_ev_group = xEventGroupCreate();
    s_init_done = true;
}

wifi_verify_result_t wifi_verify_password(const char *ssid, const char *password, const uint8_t *bssid, uint32_t timeout_ms) {
    wifi_verify_result_t result = { .status = WIFI_VERIFY_ERROR, .disconnect_reason = 0 };
    
    if (!s_init_done || !ssid) return result;
    
    xEventGroupClearBits(s_ev_group, EV_GOT_IP | EV_WRONG_PASS | EV_AP_NOT_FOUND | EV_OTHER_DISC);
    s_disc_reason = 0;
    
    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, ssid, 31);
    if (password && strlen(password) > 0) {
        strncpy((char *)wifi_cfg.sta.password, password, 63);
        wifi_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
        wifi_cfg.sta.pmf_cfg.capable = true;
        wifi_cfg.sta.pmf_cfg.required = false;
    } else {
        wifi_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
    if (bssid) { wifi_cfg.sta.bssid_set = true; memcpy(wifi_cfg.sta.bssid, bssid, 6); }
    
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(200));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    
    s_expecting = true;
    esp_wifi_connect();
    
    EventBits_t bits = xEventGroupWaitBits(s_ev_group, 
        EV_GOT_IP | EV_WRONG_PASS | EV_AP_NOT_FOUND | EV_OTHER_DISC,
        pdTRUE, pdFALSE, pdMS_TO_TICKS(timeout_ms));
    s_expecting = false;
    
    if (bits & EV_GOT_IP) {
        result.status = WIFI_VERIFY_CORRECT;
        ESP_LOGI(TAG, "✅ Password CORRECT for %s", ssid);
        esp_wifi_disconnect();
    } else if (bits & EV_WRONG_PASS) {
        result.status = WIFI_VERIFY_WRONG_PASSWORD;
        result.disconnect_reason = s_disc_reason;
    } else if (bits & EV_AP_NOT_FOUND) {
        result.status = WIFI_VERIFY_AP_NOT_FOUND;
    } else {
        result.status = WIFI_VERIFY_TIMEOUT;
        esp_wifi_disconnect();
    }
    
    strncpy(result.ssid, ssid, 32);
    return result;
}

const char *wifi_verify_status_str(wifi_verify_status_t status) {
    switch (status) {
        case WIFI_VERIFY_CORRECT: return "CORRECT";
        case WIFI_VERIFY_WRONG_PASSWORD: return "WRONG_PASSWORD";
        case WIFI_VERIFY_AP_NOT_FOUND: return "AP_NOT_FOUND";
        case WIFI_VERIFY_TIMEOUT: return "TIMEOUT";
        case WIFI_VERIFY_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}
