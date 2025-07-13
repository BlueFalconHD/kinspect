#pragma once

#include <stdbool.h>

bool TerminalSupportsFormatting(void);

/*
    Control          Code
    RESET               0
    BOLD                1
    DIM                 2
    ITALIC              3
    UNDERLINE           4
    BLINK               5
    REVERSE             7
    HIDDEN              8
    STRIKETHROUGH       9

    Base colors      Code
    BLACK               0
    RED                 1
    GREEN               2
    YELLOW              3
    BLUE                4
    MAGENTA             5
    CYAN                6
    WHITE               7

    Format types   Oe
    Foreground         30
    Background         40
    Bright             60
*/

// ANSI color codes
#define afBLACK "\033[30m"
#define afRED "\033[31m"
#define afGREEN "\033[32m"
#define afYELLOW "\033[33m"
#define afBLUE "\033[34m"
#define afMAGENTA "\033[35m"
#define afCYAN "\033[36m"
#define afWHITE "\033[37m"
#define abBLACK "\033[40m"
#define abRED "\033[41m"
#define abGREEN "\033[42m"
#define abYELLOW "\033[43m"
#define abBLUE "\033[44m"
#define abMAGENTA "\033[45m"
#define abCYAN "\033[46m"
#define abWHITE "\033[47m"
#define afBRIGHT_BLACK "\033[90m"
#define afBRIGHT_RED "\033[91m"
#define afBRIGHT_GREEN "\033[92m"
#define afBRIGHT_YELLOW "\033[93m"
#define afBRIGHT_BLUE "\033[94m"
#define afBRIGHT_MAGENTA "\033[95m"
#define afBRIGHT_CYAN "\033[96m"
#define afBRIGHT_WHITE "\033[97m"
#define abBRIGHT_BLACK "\033[100m"
#define abBRIGHT_RED "\033[101m"
#define abBRIGHT_GREEN "\033[102m"
#define abBRIGHT_YELLOW "\033[103m"
#define abBRIGHT_BLUE "\033[104m"
#define abBRIGHT_MAGENTA "\033[105m"
#define abBRIGHT_CYAN "\033[106m"
#define abBRIGHT_WHITE "\033[107m"

// ANSI control codes
#define aRESET "\033[0m"
#define aBOLD "\033[1m"
#define aDIM "\033[2m"
#define aITALIC "\033[3m"
#define aUNDERLINE "\033[4m"
#define aBLINK "\033[5m"
#define aREVERSE "\033[7m"
#define aHIDDEN "\033[8m"
#define aSTRIKETHROUGH "\033[9m"
