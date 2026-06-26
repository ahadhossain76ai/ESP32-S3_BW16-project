#include "buzzer_led.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

void hw_init(void) {
    gpio_reset_pin(BUZZER_PIN);
    gpio_reset_pin(LED_PIN);
    gpio_set_direction(BUZZER_PIN, GPIO_MODE_OUTPUT);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(BUZZER_PIN, 0);
    gpio_set_level(LED_PIN, 0);
}

void hw_led_on(void) { gpio_set_level(LED_PIN, 1); }
void hw_led_off(void) { gpio_set_level(LED_PIN, 0); }

void hw_led_blink(int times, int delay_ms) {
    for (int i = 0; i < times; i++) {
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

void hw_buzzer_on(void) { gpio_set_level(BUZZER_PIN, 1); }
void hw_buzzer_off(void) { gpio_set_level(BUZZER_PIN, 0); }

void hw_buzzer_beep(int times, int delay_ms) {
    for (int i = 0; i < times; i++) {
        gpio_set_level(BUZZER_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
        gpio_set_level(BUZZER_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

void hw_success_alert(void) {
    for (int i = 0; i < 3; i++) {
        gpio_set_level(BUZZER_PIN, 1);
        gpio_set_level(LED_PIN, 1);
        vTaskDelay(pdMS_TO_TICKS(150));
        gpio_set_level(BUZZER_PIN, 0);
        gpio_set_level(LED_PIN, 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    gpio_set_level(BUZZER_PIN, 1);
    gpio_set_level(LED_PIN, 1);
    vTaskDelay(pdMS_TO_TICKS(500));
    gpio_set_level(BUZZER_PIN, 0);
    gpio_set_level(LED_PIN, 0);
}

void hw_fail_alert(void) {
    hw_buzzer_beep(2, 100);
}
