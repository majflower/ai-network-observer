#!/bin/bash
set -e

echo "========================================"
echo "AI-Driven Network Observability Agent"
echo "========================================"
echo ""

# Check if running as root (needed for packet capture)
if [ "$(id -u)" != "0" ]; then
    echo "WARNING: Not running as root. Packet capture may fail."
    echo "Use: docker run --cap-add=NET_ADMIN --cap-add=NET_RAW ..."
fi

# Check network interface
if [ -n "$CAPTURE_INTERFACE" ]; then
    echo "Checking interface: $CAPTURE_INTERFACE"
    if ! ip link show "$CAPTURE_INTERFACE" > /dev/null 2>&1; then
        echo "ERROR: Interface $CAPTURE_INTERFACE not found"
        echo "Available interfaces:"
        ip link show
        exit 1
    fi
    echo "✓ Interface $CAPTURE_INTERFACE is available"
fi

# Check API key if LLM enabled
#if [ "$ENABLE_LLM" = "true" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
    # echo "WARNING: ENABLE_LLM is true but ANTHROPIC_API_KEY is not set"
    # echo "LLM analysis will be disabled"
# fi

# Create output directories
mkdir -p "$OUTPUT_DIR" "$LOG_DIR"

echo ""
echo "Configuration:"
echo "  Interface: ${CAPTURE_INTERFACE:-not set}"
echo "  Session Duration: ${SESSION_DURATION:-30} minutes"
echo "  LLM Enabled: ${ENABLE_LLM:-false}"
echo "  Performance Mode: ${PERFORMANCE_MODE:-false}"
echo "  Log Level: ${LOG_LEVEL:-INFO}"
echo ""

# If no arguments provided, show help
if [ $# -eq 0 ]; then
    python src/main.py --help
    exit 0
fi

# Run the application
exec python src/main.py "$@"
