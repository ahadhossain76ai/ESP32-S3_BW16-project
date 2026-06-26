#ifndef BUZZER_LED_H
#define BUZZER_LED_H

#include "driver/gpio.h"

#define BUZZER_PIN  GPIO_NUM_4
#define LED_PIN     GPIO_NUM_2

void hw_init(void);
void hw_led_on(void);
void hw_led_off(void);
void hw_led_blink(int times, int delay_ms);
void hw_buzzer_on(void);
void hw_buzzer_off(void);
void hw_buzzer_beep(int times, int delay_ms);
void hw_success_alert(void);
void hw_fail_alert(void);

#endif
