/*
 * attack_ducky.c — USB Rubber Ducky / BadUSB HID injection
 */

#include "attack_ducky.h"
#include "esp_log.h"
#include "tinyusb.h"
#include "class/hid/hid_device.h"
#include <string.h>
#include <stdlib.h>

static const char *TAG = "DUCKY";

static volatile bool g_ducky_running = false;

// HID keyboard report buffer
static uint8_t hid_keyboard_report[8] = { 0 };

static void hid_send_report(void) {
    tud_hid_n_report(0, 1, hid_keyboard_report, sizeof(hid_keyboard_report));
}

static void release_all(void) {
    memset(hid_keyboard_report, 0, sizeof(hid_keyboard_report));
    hid_send_report();
    esp_rom_delay_us(10000);
}

static void press_key(uint8_t modifier, uint8_t keycode) {
    hid_keyboard_report[0] = modifier;
    hid_keyboard_report[2] = keycode;
    hid_send_report();
    esp_rom_delay_us(20000);
    release_all();
    esp_rom_delay_us(10000);
}

// HID keycode lookup table (US layout)
static const uint8_t hid_keycodes_ascii[128] = {
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x2c,0x1e,0x34,0x20,0x21,0x22,0x24,0x34,
    0x26,0x27,0x25,0x2e,0x36,0x2d,0x37,0x38,
    0x27,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,
    0x25,0x26,0x37,0x36,0x38,0x2d,0x37,0x38,
    0x1f,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
    0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,
    0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,
    0x1b,0x1c,0x1d,0x2e,0x1e,0x2f,0x1f,0x21,
    0x22,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
    0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,
    0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,
    0x1b,0x1c,0x1d,0x2e,0x1e,0x2f,0x1f,0x21,
};

static bool needs_shift(char c) {
    if (c >= 'A' && c <= 'Z') return true;
    switch(c) {
        case '!': case '@': case '#': case '$': case '%':
        case '^': case '&': case '*': case '(': case ')':
        case '_': case '+': case '{': case '}': case '|':
        case ':': case '"': case '~': case '<': case '>': case '?':
            return true;
        default: return false;
    }
}

static uint8_t char_to_hid(unsigned char c, uint8_t *mod) {
    *mod = 0;
    if (c >= 128) return 0;
    uint8_t hid = hid_keycodes_ascii[c];
    if (hid == 0) return 0;
    if (needs_shift(c)) *mod = 0x02;
    return hid;
}

static void type_char(unsigned char c) {
    uint8_t mod;
    uint8_t hid = char_to_hid(c, &mod);
    if (hid == 0) return;
    press_key(mod, hid);
}

static void type_string(const char *str) {
    while (*str) { type_char((unsigned char)*str); str++; }
}

static uint8_t named_key_to_hid(const char *name) {
    if (strcasecmp(name, "ENTER")==0) return 0x28;
    if (strcasecmp(name, "SPACE")==0) return 0x2c;
    if (strcasecmp(name, "TAB")==0) return 0x2b;
    if (strcasecmp(name, "ESC")==0||strcasecmp(name, "ESCAPE")==0) return 0x29;
    if (strcasecmp(name, "BACKSPACE")==0) return 0x2a;
    if (strcasecmp(name, "DELETE")==0||strcasecmp(name, "DEL")==0) return 0x4c;
    if (strcasecmp(name, "UP")==0) return 0x52;
    if (strcasecmp(name, "DOWN")==0) return 0x51;
    if (strcasecmp(name, "LEFT")==0) return 0x50;
    if (strcasecmp(name, "RIGHT")==0) return 0x4f;
    if (strcasecmp(name, "HOME")==0) return 0x4a;
    if (strcasecmp(name, "END")==0) return 0x4d;
    if (strcasecmp(name, "PAGEUP")==0||strcasecmp(name, "PAGE_UP")==0) return 0x4b;
    if (strcasecmp(name, "PAGEDOWN")==0||strcasecmp(name, "PAGE_DOWN")==0) return 0x4e;
    if (strcasecmp(name, "F1")==0) return 0x3a;
    if (strcasecmp(name, "F2")==0) return 0x3b;
    if (strcasecmp(name, "F3")==0) return 0x3c;
    if (strcasecmp(name, "F4")==0) return 0x3d;
    if (strcasecmp(name, "F5")==0) return 0x3e;
    if (strcasecmp(name, "F6")==0) return 0x3f;
    if (strcasecmp(name, "F7")==0) return 0x40;
    if (strcasecmp(name, "F8")==0) return 0x41;
    if (strcasecmp(name, "F9")==0) return 0x42;
    if (strcasecmp(name, "F10")==0) return 0x43;
    if (strcasecmp(name, "F11")==0) return 0x44;
    if (strcasecmp(name, "F12")==0) return 0x45;
    return 0;
}

static uint8_t mod_name_to_bit(const char *name) {
    if (strcasecmp(name, "CTRL")==0||strcasecmp(name, "CONTROL")==0) return 0x01;
    if (strcasecmp(name, "SHIFT")==0) return 0x02;
    if (strcasecmp(name, "ALT")==0) return 0x04;
    if (strcasecmp(name, "GUI")==0||strcasecmp(name, "WINDOWS")==0||strcasecmp(name, "COMMAND")==0) return 0x08;
    return 0;
}

// ==================== DUCKY SCRIPT PARSER ====================
typedef enum {
    DUCKY_GUI, DUCKY_CTRL, DUCKY_SHIFT, DUCKY_ALT,
    DUCKY_WINDOWS, DUCKY_COMMAND,
    DUCKY_ENTER, DUCKY_SPACE, DUCKY_TAB, DUCKY_ESCAPE,
    DUCKY_DELAY, DUCKY_STRING, DUCKY_REPEAT, DUCKY_UNKNOWN
} ducky_cmd_t;

typedef struct { const char *name; ducky_cmd_t cmd; } ducky_keyword_t;

static const ducky_keyword_t g_keywords[] = {
    {"GUI", DUCKY_GUI}, {"CTRL", DUCKY_CTRL}, {"CONTROL", DUCKY_CTRL},
    {"SHIFT", DUCKY_SHIFT}, {"ALT", DUCKY_ALT},
    {"WINDOWS", DUCKY_WINDOWS}, {"COMMAND", DUCKY_COMMAND},
    {"ENTER", DUCKY_ENTER}, {"SPACE", DUCKY_SPACE},
    {"TAB", DUCKY_TAB}, {"ESCAPE", DUCKY_ESCAPE}, {"ESC", DUCKY_ESCAPE},
    {"DELAY", DUCKY_DELAY}, {"STRING", DUCKY_STRING},
    {"REPEAT", DUCKY_REPEAT}, {NULL, DUCKY_UNKNOWN}
};

static ducky_cmd_t parse_command(const char *token) {
    for (int i = 0; g_keywords[i].name; i++) {
        if (strcasecmp(token, g_keywords[i].name) == 0)
            return g_keywords[i].cmd;
    }
    return DUCKY_UNKNOWN;
}

static int execute_line(const char *line) {
    char buf[256];
    strncpy(buf, line, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr;
    char *token = strtok_r(buf, " \t\r\n", &saveptr);
    if (!token) return 0;

    ducky_cmd_t cmd = parse_command(token);
    
    switch (cmd) {
        case DUCKY_STRING: {
            char *str = strtok_r(NULL, "\n\r", &saveptr);
            if (str) { while (*str == ' ') str++; type_string(str); }
            break;
        }
        case DUCKY_ENTER: press_key(0, 0x28); break;
        case DUCKY_SPACE: type_char(' '); break;
        case DUCKY_TAB: press_key(0, 0x2b); break;
        case DUCKY_ESCAPE: press_key(0, 0x29); break;
        case DUCKY_DELAY: {
            char *ms_str = strtok_r(NULL, " \t\r\n", &saveptr);
            if (ms_str) vTaskDelay(pdMS_TO_TICKS(atoi(ms_str)));
            break;
        }
        case DUCKY_GUI: case DUCKY_CTRL: case DUCKY_SHIFT:
        case DUCKY_ALT: case DUCKY_WINDOWS: case DUCKY_COMMAND: {
            char *key = strtok_r(NULL, " \t\r\n", &saveptr);
            if (key) {
                uint8_t mod = mod_name_to_bit(token);
                uint8_t kc = named_key_to_hid(key);
                if (kc == 0 && strlen(key) == 1) {
                    uint8_t char_mod;
                    kc = char_to_hid((unsigned char)key[0], &char_mod);
                    mod |= char_mod;
                }
                if (kc) press_key(mod, kc);
            }
            break;
        }
        default: break;
    }
    return 0;
}

// ==================== REQUIRED TINYUSB HID CALLBACKS ====================

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance) {
    static const uint8_t desc_hid_report[] = {
        TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(1))
    };
    return desc_hid_report;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                                hid_report_type_t report_type, uint8_t *buffer, uint16_t reqlen) {
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                            hid_report_type_t report_type, uint8_t const *buffer, uint16_t bufsize) {
    // Not used
}

// ==================== PUBLIC API ====================

int ducky_inject(const char *script) {
    if (!script || !*script) {
        ESP_LOGE(TAG, "Empty or NULL script");
        return -1;
    }
    
    g_ducky_running = true;
    ESP_LOGI(TAG, "Ducky injection STARTED (script length: %d bytes)", strlen(script));
    
    char *copy = strdup(script);
    if (!copy) {
        g_ducky_running = false;
        return -1;
    }
    
    char *saveptr;
    char *line = strtok_r(copy, "\n\r", &saveptr);
    int line_count = 0;
    
    while (line && g_ducky_running) {
        // Trim leading whitespace
        while (*line == ' ' || *line == '\t') line++;
        
        // Skip empty lines and comments
        if (*line && *line != ';' && *line != '#') {
            execute_line(line);
            line_count++;
        }
        
        line = strtok_r(NULL, "\n\r", &saveptr);
    }
    
    free(copy);
    g_ducky_running = false;
    
    ESP_LOGI(TAG, "Ducky injection COMPLETE - %d lines executed", line_count);
    return line_count > 0 ? 0 : -1;
}

void ducky_stop(void) {
    g_ducky_running = false;
    release_all();
    ESP_LOGI(TAG, "Ducky injection stopped");
}

bool ducky_is_running(void) {
    return g_ducky_running;
}