/**
 * @file main.c
 * @brief ESP32-S3 Master + BW16 RTL8720DN - WiFi Pentest Tool
 * 
 * Dual-band WiFi pentest platform with Web UI
 * 2.4GHz: ESP32-S3 native
 * 5GHz: BW16 via UART
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_spiffs.h"
#include "tinyusb.h"
#include "attack.h"
#include "wifi_controller.h"
#include "webserver.h"
#include "utils/bw16_uart.h"
#include "hardware/buzzer_led.h"
#include "attack_deauth.h"
#include "attack_eviltwin.h"
#include "attack_beacon_spam.h"
#include "attack_jammer.h"
#include "attack_bluetooth_jammer.h"
#include "attack_ducky.h"
#include "attack_pmkid.h"
#include "wifi_pass_verifier.h"

static const char* TAG = "MAIN";

// Try multiple baud rates
static int baud_rates[] = {115200, 921600, 9600, 57600, 230400};

static bool bw16_detect_at_baud(int baud) {
    uart_set_baudrate(UART_NUM_2, baud);
    vTaskDelay(pdMS_TO_TICKS(100));
    uart_write_bytes(UART_NUM_2, "AT\r\n", 4);
    uint8_t buf[32];
    int len = uart_read_bytes(UART_NUM_2, buf, sizeof(buf) - 1, pdMS_TO_TICKS(500));
    if (len > 0) buf[len] = 0;
    return (len > 0 && strstr((char*)buf, "OK") != NULL);
}

// Mount SPIFFS for file storage
static void mount_spiffs(void) {
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = "spiffs",
        .max_files = 10,
        .format_if_mount_failed = true
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Failed to mount or format filesystem");
        } else if (ret == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "Failed to find SPIFFS partition");
        } else {
            ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
        }
        return;
    }

    size_t total = 0, used = 0;
    ret = esp_spiffs_info("spiffs", &total, &used);
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "SPIFFS: %d KB total, %d KB used", total / 1024, used / 1024);
    } else {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition info (%s)", esp_err_to_name(ret));
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, " Dual-Band WiFi Pentest Tool v3.0");
    ESP_LOGI(TAG, " ESP32-S3 (N16R8) + BW16 RTL8720DN");
    ESP_LOGI(TAG, " 2.4GHz: ESP32-S3 | 5GHz: BW16 via UART");
    ESP_LOGI(TAG, "============================================");

    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Mount SPIFFS
    mount_spiffs();

    // Initialize hardware (buzzer GPIO4, LED GPIO2)
    hw_init();

    // Initialize UART for BW16 communication
    bw16_uart_init();

    // Try multiple baud rates to detect BW16
    bool bw16_found = false;
    for (int i = 0; i < sizeof(baud_rates)/sizeof(baud_rates[0]); i++) {
        if (bw16_detect_at_baud(baud_rates[i])) {
            ESP_LOGI(TAG, "✅ BW16 detected at %d baud", baud_rates[i]);
            bw16_found = true;
            break;
        }
    }

    // Start Management AP (Soft AP always active)
    wifictl_mgmt_ap_start();

    // Initialize all attack modules
    attack_init();
    pmkid_capture_init();

    // Password verifier for EvilTwin
    wifi_verify_init();

    // Auto-connect to saved home router if credentials exist
    wifictl_auto_connect_saved();

    // Initialize TinyUSB for HID (WiFi Duck)
    tinyusb_config_t tusb_cfg = {
        .port = TINYUSB_PORT_FULL_SPEED_0,
        .task = {
            .size = 4096,
            .priority = 5,
            .xCoreID = 0,
        },
    };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));
    vTaskDelay(pdMS_TO_TICKS(200));

    ESP_LOGI(TAG, "TinyUSB HID initialized — plug USB into host for WiFi Duck");

    // Start web server
    webserver_start();

    // Check BW16 connection
    vTaskDelay(pdMS_TO_TICKS(500));
    if (bw16_found) {
        ESP_LOGI(TAG, "✅ BW16 RTL8720DN connected on UART2");
        hw_led_blink(2, 100);
    } else {
        ESP_LOGW(TAG, "⚠️ BW16 not detected. 5GHz features disabled.");
        hw_led_blink(1, 500);
    }

    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "✅ SYSTEM READY");
    ESP_LOGI(TAG, "📡 Web UI: http://192.168.4.1");
    ESP_LOGI(TAG, "📡 AP SSID: hydra / Password: notforfun");
    ESP_LOGI(TAG, "🔋 Buzzer: GPIO4 | LED: GPIO2");
    ESP_LOGI(TAG, "🔗 UART2: TX=GPIO17 RX=GPIO18 @115200");
    ESP_LOGI(TAG, "============================================");

    hw_success_alert();
}