#include <capstone.h>
#include <kextrw.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <IOKit/IOKitLib.h>
#include <mach/kern_return.h>
#include <mach/mach.h>

#include "Logging.h"
#include "Terminal.h"

static Logger *logger = NULL;

int main(void) {
  logger = createDefaultLogger("kinspect");

  logInfo(logger, "Welcome to " aBOLD afBLUE "kinspect" aRESET "!");

  if (!logger) {
    printf("fatal: Failed to create logger\n");
    return 1;
  }

  if (kextrw_init() == -1) {
    logFatal(logger, "KextRW initialization failed");
    return 1;
  }

  uint64_t kbase = get_kernel_base();
  if (!kbase) {
    logFatal(logger, "Failed to get kernel base address");
    kextrw_deinit();
    return 1;
  }
  logDebug(logger, "Kernel base address: " aBOLD afMAGENTA "0x%llx" aRESET,
           kbase);

  csh handle;
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    logFatal(logger, "Failed to initialize Capstone disassembler");
    kextrw_deinit();
    return 1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  logInfo(logger, "Bye!");
  cs_close(&handle);
  kextrw_deinit();

  return 0;
}
