/*
 * wa-mini - Minimal WhatsApp Primary Device
 * Version Information
 *
 * Copyright (c) 2025, Renaud Allard <renaud@allard.it>
 * BSD 2-Clause License
 *
 * Note: Automatic version updates are disabled because the registration
 * token (HMAC key) must be extracted from the native library for each
 * WhatsApp version. Updating the version without the corresponding key
 * will cause registration to fail with "bad_token" errors.
 *
 * To update to a new WhatsApp version:
 * 1. Download the new WhatsApp APK
 * 2. Extract MD5_CLASSES: md5sum classes.dex | base64
 * 3. Extract WA_KEY from libwhatsappmerged.so (requires Frida or Ghidra)
 * 4. Update src/register.c with new WA_VERSION, WA_MD5_CLASSES, and WA_KEY
 * 5. Rebuild: make clean && make
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wa-mini.h"

/*
 * Build user-agent string
 */
int wa_build_user_agent(const char *version, char *ua, size_t size)
{
    /* Format: WhatsApp/2.26.4.71 Android/14 Device/Google_Pixel_8 */
    snprintf(ua, size, "WhatsApp/%s Android/14 Device/Google_Pixel_8", version);
    return 0;
}
