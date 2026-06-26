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
    ret = esp_spiffs_info(NULL, &total, &used);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to get SPIFFS partition info (%s)", esp_err_to_name(ret));
    } else {
        ESP_LOGI(TAG, "SPIFFS mounted: %d KB total, %d KB used", total / 1024, used / 1024);
    }
}

void app_main(void) {
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "   Dual-Band WiFi Pentest Tool v3.0");
    ESP_LOGI(TAG, "   ESP32-S3 (N16R8) + BW16 RTL8720DN");
    ESP_LOGI(TAG, "   2.4GHz: ESP32-S3 | 5GHz: BW16 via UART");
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
    
    // Start Management AP (Soft AP always active)
    wifictl_mgmt_ap_start();
    
    // Auto-connect to saved home router if credentials exist
    wifictl_auto_connect_saved();
    
    // Initialize all attack modules
    attack_init();

    pmkid_capture_init();
    
    // Password verifier for EvilTwin
    wifi_verify_init();

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
    
    // Start web server
    webserver_start();
    
    // Check BW16 connection
    vTaskDelay(pdMS_TO_TICKS(500));
    bw16_send_command("PING\n");
    vTaskDelay(pdMS_TO_TICKS(300));
    
    if (bw16_is_connected()) {
        ESP_LOGI(TAG, "✅ BW16 RTL8720DN connected on UART2");
        hw_led_blink(2, 100); // 2 fast blinks = BW16 connected
    } else {
        ESP_LOGW(TAG, "⚠️  BW16 not detected. 5GHz features disabled.");
        hw_led_blink(1, 500); // 1 slow blink = no BW16
    }
    
    ESP_LOGI(TAG, "============================================");
    ESP_LOGI(TAG, "✅ SYSTEM READY");
    ESP_LOGI(TAG, "📡 Web UI: http://192.168.4.1");
    ESP_LOGI(TAG, "📡 AP SSID: hydra  /  Password: notforfun");
    ESP_LOGI(TAG, "🔋 Buzzer: GPIO4  |  LED: GPIO2");
    ESP_LOGI(TAG, "🔗 UART2: TX=GPIO17  RX=GPIO18 @115200");
    ESP_LOGI(TAG, "============================================");
    
    // Success indicator
    hw_success_alert();
}
