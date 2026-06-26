#ifndef DEBUG_H
#define DEBUG_H

// Uncomment for debug serial output
#define DEBUG

#ifdef DEBUG
  #define DEBUG_SER_INIT() Serial.begin(115200)
  #define DEBUG_SER_PRINT(x) Serial.print(x)
  #define DEBUG_SER_PRINTLN(x) Serial.println(x)
#else
  #define DEBUG_SER_INIT()
  #define DEBUG_SER_PRINT(x)
  #define DEBUG_SER_PRINTLN(x)
#endif

#endif
