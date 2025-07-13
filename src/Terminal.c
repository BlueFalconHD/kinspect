#include "Terminal.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool terminalSupportsFormattingCached = false;
static bool terminalSupportsFormattingCachedValue = false;

bool TerminalSupportsFormatting(void) {
  if (terminalSupportsFormattingCached) {
    return terminalSupportsFormattingCachedValue;
  }

  if (!isatty(STDOUT_FILENO)) {
    terminalSupportsFormattingCached = true;
    terminalSupportsFormattingCachedValue = false;
    return false;
  }

  if (getenv("NO_COLOR")) {
    terminalSupportsFormattingCached = true;
    terminalSupportsFormattingCachedValue = false;
    return false;
  }

  const char *term = getenv("TERM");
  if (!term || strcmp(term, "dumb") == 0) {
    terminalSupportsFormattingCached = true;
    terminalSupportsFormattingCachedValue = false;
    return false;
  }

  if (getenv("COLORTERM")) {
    terminalSupportsFormattingCached = true;
    terminalSupportsFormattingCachedValue = true;
    return true;
  }

  terminalSupportsFormattingCached = true;
  terminalSupportsFormattingCachedValue = true;
  return true;
}
