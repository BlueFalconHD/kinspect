#!/bin/bash
MATE_URL="https://raw.githubusercontent.com/TomasBorquez/mate.h/refs/heads/master/mate.h"
MATE_OUTPUT_FILE="mate.h"

if command -v curl &> /dev/null; then
    curl -o "$MATE_OUTPUT_FILE" "$MATE_URL"
elif command -v wget &> /dev/null; then
    wget -O "$MATE_OUTPUT_FILE" "$MATE_URL"
else
    echo "Error: Neither curl nor wget is installed."
    exit 1
fi
