#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    COMMAND_EXPR,
    COMMAND_MEMORY,
    COMMAND_DISASSEMBLE,
    COMMAND_KBASE,
    COMMAND_HELP,
    COMMAND_UNKNOWN
} CommandType;

typedef enum {
    ARG_TYPE_STRING, // "..."
    ARG_TYPE_INT, // [0-9]+
    ARG_TYPE_FLOAT, // [0-9]+.[0-9]+
    ARG_TYPE_EXPRESSION, // \[...\]
    ARG_TYPE_VAR // $[a-zA-Z_][a-zA-Z0-9_]*
} ArgType;
