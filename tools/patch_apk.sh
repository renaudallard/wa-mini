#!/bin/bash
#
# patch_apk.sh - Patch WhatsApp APK with Frida Gadget for key extraction
#
# This script injects Frida Gadget into a WhatsApp APK, allowing runtime
# key extraction without a rooted device.
#
# Usage: ./patch_apk.sh <WhatsApp.apk> [architecture]
#
# Arguments:
#   WhatsApp.apk    Path to the original WhatsApp APK
#   architecture    Target architecture (default: arm64-v8a)
#                   Options: arm64-v8a, armeabi-v7a, x86_64, x86
#
# Requirements:
#   - apktool (APK decompilation)
#   - zipalign (APK alignment)
#   - apksigner or jarsigner (APK signing)
#   - wget or curl (downloading Frida gadget)
#   - xz (decompression)
#
# Output: WhatsApp_patched.apk in current directory

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
FRIDA_VERSION="16.6.6"
DEFAULT_ARCH="arm64-v8a"

usage() {
    echo "Usage: $0 <WhatsApp.apk> [architecture]"
    echo ""
    echo "Arguments:"
    echo "  WhatsApp.apk    Path to the original WhatsApp APK"
    echo "  architecture    Target architecture (default: arm64-v8a)"
    echo "                  Options: arm64-v8a, armeabi-v7a, x86_64, x86"
    echo ""
    echo "Example:"
    echo "  $0 ~/Downloads/WhatsApp.apk arm64-v8a"
    exit 1
}

log() {
    echo -e "${GREEN}[+]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[-]${NC} $1"
    exit 1
}

check_requirements() {
    log "Checking requirements..."

    local missing=""

    command -v apktool >/dev/null 2>&1 || missing="$missing apktool"
    command -v zipalign >/dev/null 2>&1 || missing="$missing zipalign"
    command -v xz >/dev/null 2>&1 || missing="$missing xz"

    # Check for signing tool
    if ! command -v apksigner >/dev/null 2>&1; then
        if ! command -v jarsigner >/dev/null 2>&1; then
            missing="$missing apksigner/jarsigner"
        fi
    fi

    # Check for download tool
    if ! command -v wget >/dev/null 2>&1; then
        if ! command -v curl >/dev/null 2>&1; then
            missing="$missing wget/curl"
        fi
    fi

    if [ -n "$missing" ]; then
        error "Missing required tools:$missing\n\nInstall with:\n  sudo apt install apktool zipalign apksigner wget xz-utils"
    fi

    log "All requirements satisfied"
}

download_frida_gadget() {
    local arch=$1
    local gadget_name="frida-gadget-${FRIDA_VERSION}-android-${arch}.so"
    local gadget_url="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${gadget_name}.xz"

    if [ -f "$gadget_name" ]; then
        log "Frida gadget already downloaded: $gadget_name"
        return
    fi

    log "Downloading Frida gadget v${FRIDA_VERSION} for ${arch}..."

    if command -v wget >/dev/null 2>&1; then
        wget -q --show-progress "$gadget_url" -O "${gadget_name}.xz"
    else
        curl -L --progress-bar "$gadget_url" -o "${gadget_name}.xz"
    fi

    log "Decompressing..."
    xz -d "${gadget_name}.xz"

    log "Frida gadget ready: $gadget_name"
}

# Map architecture names
get_frida_arch() {
    case "$1" in
        arm64-v8a) echo "arm64" ;;
        armeabi-v7a) echo "arm" ;;
        x86_64) echo "x86_64" ;;
        x86) echo "x86" ;;
        *) echo "$1" ;;
    esac
}

find_main_activity() {
    local manifest="$1/AndroidManifest.xml"

    # Extract main activity from manifest
    grep -oP 'android:name="\K[^"]+(?="[^>]*>[\s\S]*?<intent-filter[\s\S]*?android.intent.action.MAIN)' "$manifest" | head -1
}

inject_loader() {
    local smali_dir="$1"
    local activity="$2"

    # Convert activity name to smali path
    local smali_path="${smali_dir}/$(echo "$activity" | tr '.' '/').smali"

    # Try different smali directories (smali, smali_classes2, etc.)
    if [ ! -f "$smali_path" ]; then
        for dir in "$smali_dir"/../smali_classes*; do
            local alt_path="${dir}/$(echo "$activity" | tr '.' '/').smali"
            if [ -f "$alt_path" ]; then
                smali_path="$alt_path"
                break
            fi
        done
    fi

    if [ ! -f "$smali_path" ]; then
        warn "Could not find main activity smali, searching for Application class..."

        # Try to find Application class
        smali_path=$(find "$smali_dir"/.. -name "*.smali" -exec grep -l "Landroid/app/Application;" {} \; | head -1)

        if [ -z "$smali_path" ]; then
            error "Could not find suitable class to inject loader"
        fi
    fi

    log "Injecting loader into: $smali_path"

    # Check if already injected
    if grep -q "frida-gadget" "$smali_path"; then
        warn "Frida gadget loader already present"
        return
    fi

    # Find or create static constructor
    if grep -q "\.method static constructor <clinit>" "$smali_path"; then
        # Add to existing static constructor
        sed -i '/\.method static constructor <clinit>/,/\.end method/{
            /\.locals/a\
\
    # Load Frida gadget\
    const-string v0, "frida-gadget"\
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
        }' "$smali_path"
    else
        # Find .method public constructor or any method to insert before
        sed -i '0,/^\.method/{s/^\.method/# Load Frida gadget\n.method static constructor <clinit>()V\n    .locals 1\n\n    const-string v0, "frida-gadget"\n    invoke-static {v0}, Ljava\/lang\/System;->loadLibrary(Ljava\/lang\/String;)V\n\n    return-void\n.end method\n\n.method/}' "$smali_path"
    fi

    log "Loader injected successfully"
}

create_gadget_config() {
    local lib_dir="$1"

    # Create config to auto-load script
    cat > "${lib_dir}/libfrida-gadget.config.so" << 'EOF'
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_load": "wait"
  }
}
EOF

    log "Created Frida gadget config"
}

sign_apk() {
    local apk="$1"
    local signed_apk="$2"

    log "Signing APK..."

    # Create a temporary keystore if needed
    local keystore="$HOME/.android/debug.keystore"
    if [ ! -f "$keystore" ]; then
        log "Creating debug keystore..."
        mkdir -p "$HOME/.android"
        keytool -genkey -v -keystore "$keystore" \
            -storepass android -alias androiddebugkey -keypass android \
            -keyalg RSA -keysize 2048 -validity 10000 \
            -dname "CN=Android Debug,O=Android,C=US" 2>/dev/null
    fi

    if command -v apksigner >/dev/null 2>&1; then
        apksigner sign --ks "$keystore" --ks-pass pass:android \
            --key-pass pass:android --out "$signed_apk" "$apk"
    else
        jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
            -keystore "$keystore" -storepass android \
            -keypass android "$apk" androiddebugkey
        mv "$apk" "$signed_apk"
    fi

    log "APK signed: $signed_apk"
}

main() {
    if [ $# -lt 1 ]; then
        usage
    fi

    local input_apk="$1"
    local arch="${2:-$DEFAULT_ARCH}"
    local frida_arch=$(get_frida_arch "$arch")

    if [ ! -f "$input_apk" ]; then
        error "APK not found: $input_apk"
    fi

    echo ""
    echo "=========================================="
    echo "  WhatsApp APK Patcher for Frida Gadget"
    echo "=========================================="
    echo ""
    log "Input APK: $input_apk"
    log "Target architecture: $arch"
    echo ""

    check_requirements

    # Create working directory
    local work_dir=$(mktemp -d)
    local apk_name=$(basename "$input_apk" .apk)
    local decompiled_dir="${work_dir}/${apk_name}"

    trap "rm -rf '$work_dir'" EXIT

    # Download Frida gadget
    cd "$work_dir"
    download_frida_gadget "$frida_arch"
    local gadget_so="frida-gadget-${FRIDA_VERSION}-android-${frida_arch}.so"

    # Decompile APK
    log "Decompiling APK (this may take a while)..."
    apktool d -f "$input_apk" -o "$decompiled_dir" 2>/dev/null

    # Copy Frida gadget to lib directory
    local lib_dir="${decompiled_dir}/lib/${arch}"
    mkdir -p "$lib_dir"
    cp "$gadget_so" "${lib_dir}/libfrida-gadget.so"
    log "Copied Frida gadget to ${lib_dir}"

    # Create gadget config
    create_gadget_config "$lib_dir"

    # Find and inject loader
    local main_activity=$(find_main_activity "$decompiled_dir")
    if [ -n "$main_activity" ]; then
        log "Found main activity: $main_activity"
    fi
    inject_loader "${decompiled_dir}/smali" "${main_activity:-com.whatsapp.Main}"

    # Rebuild APK
    log "Rebuilding APK..."
    local rebuilt_apk="${work_dir}/${apk_name}_rebuilt.apk"
    apktool b "$decompiled_dir" -o "$rebuilt_apk" 2>/dev/null

    # Align APK
    log "Aligning APK..."
    local aligned_apk="${work_dir}/${apk_name}_aligned.apk"
    zipalign -f 4 "$rebuilt_apk" "$aligned_apk"

    # Sign APK
    local output_apk="$(pwd)/WhatsApp_patched.apk"
    cd - >/dev/null
    sign_apk "$aligned_apk" "$output_apk"

    echo ""
    echo "=========================================="
    echo "  Patching Complete!"
    echo "=========================================="
    echo ""
    log "Output: $output_apk"
    echo ""
    echo "Next steps:"
    echo "  1. Uninstall existing WhatsApp: adb uninstall com.whatsapp"
    echo "  2. Install patched APK: adb install $output_apk"
    echo "  3. Start WhatsApp on device (it will wait for Frida)"
    echo "  4. Connect Frida: frida -U Gadget -l frida_extract_key.js"
    echo "  5. In WhatsApp: Enter phone number, tap Next"
    echo "  6. Key will be captured and displayed!"
    echo ""
}

main "$@"
