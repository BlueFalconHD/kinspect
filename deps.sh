#!/bin/bash
URL="https://raw.githubusercontent.com/TomasBorquez/mate.h/refs/heads/master/mate.h"
OUTPUT_FILE="mate.h"

if command -v curl &> /dev/null; then
    curl -o "$OUTPUT_FILE" "$URL"
elif command -v wget &> /dev/null; then
    wget -O "$OUTPUT_FILE" "$URL"
else
    echo "Error: Neither curl nor wget is installed."
    exit 1
fi
