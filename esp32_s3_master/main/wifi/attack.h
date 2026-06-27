#ifndef ATTACK_H
#define ATTACK_H

#include "esp_wifi_types.h"
#include <stdbool.h>
#include <stdint.h>

#define MAX_ATTACK_TARGETS 10

typedef struct {
    wifi_ap_record_t *ap_records[MAX_ATTACK_TARGETS];
    int target_count;
    int method;
} attack_config_t;

extern int g_scan_result_count;
extern wifi_ap_record_t *g_scan_results;
extern wifi_ap_record_t g_first_ap;
extern volatile bool g_scanning;

void attack_init(void);
void attack_scan_start(void);
bool attack_is_scanning(void);
void attack_dos_start_broadcast(void);
void attack_dos_stop(void);
bool attack_dos_is_running(void);

// ==================== AUTO ATTACK CHAIN ====================
typedef enum {
    ATTACK_CHAIN_IDLE = 0,
    ATTACK_CHAIN_SCANNING,
    ATTACK_CHAIN_DEAUTHING,
    ATTACK_CHAIN_CAPTURING,
    ATTACK_CHAIN_COMPLETE,
    ATTACK_CHAIN_FAILED
} attack_chain_state_t;

typedef struct {
    // State
    attack_chain_state_t state;
    bool running;
    
    // Target info
    uint8_t target_bssid[6];
    char target_ssid[33];
    uint8_t target_channel;
    bool target_is_5ghz;
    
    // Chain progress
    int current_step_index;
    int step_count;
    int progress_percent;
    char step_description[64];
    
    // Attack stats
    uint32_t deauth_count;
    uint32_t packets_captured;
    bool pmkid_found;
    char last_pmkid[33];
    
    // Timing
    uint32_t start_time_ms;
    uint32_t elapsed_ms;
    esp_err_t last_error;
} attack_chain_status_t;

/**
 * @brief Start automated attack chain:
 * 1. Scan all channels
 * 2. Select strongest target
 * 3. Deauth all clients
 * 4. Capture PMKID/EAPOL handshake
 * 5. Report results
 */
void attack_chain_start(void);

/**
 * @brief Stop automated attack chain
 */
void attack_chain_stop(void);

/**
 * @brief Get current attack chain status
 */
attack_chain_status_t* attack_chain_get_status(void);

/**
 * @brief Check if attack chain is running
 */
bool attack_chain_is_running(void);

// ==================== ATTACK TEMPLATES ====================
typedef enum {
    TEMPLATE_QUICK_DEAUTH = 0,      // Deauth + PMKID capture (fast)
    TEMPLATE_FULL_SCAN,              // Full spectrum scan
    TEMPLATE_STEALTH_EVILTWIN,       // EvilTwin with auto-password verify
    TEMPLATE_MASS_BEACON,            // Large-scale beacon spam
    TEMPLATE_JAMMER_EXTREME,         // Full spectrum + BT jammer
    TEMPLATE_RECON_ALL,              // Complete reconnaissance
    TEMPLATE_CUSTOM
} attack_template_t;

typedef struct {
    attack_template_t template_id;
    const char *name;
    const char *description;
    uint32_t estimated_time_sec;
    uint8_t channels_to_scan[32];
    int channel_count;
    bool use_pmkid_capture;
    bool use_deauth;
    bool use_eviltwin;
    bool use_beacon_spam;
    bool use_jammer;
    bool use_bt_jammer;
    bool use_hid_ducky;
    bool auto_chain;
    uint8_t deauth_packets_per_target;
    uint16_t beacon_count;
} attack_template_config_t;

/**
 * @brief Get predefined attack template by ID
 */
const attack_template_config_t* attack_get_template(attack_template_t template_id);

/**
 * @brief Apply an attack template (quick configure and run)
 */
esp_err_t attack_apply_template(attack_template_t template_id);

/**
 * @brief List all available templates (for Web UI JSON)
 * Caller must free returned string
 */
char* attack_templates_list_json(void);

#endif // ATTACK_H
