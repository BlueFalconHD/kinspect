#include <capstone.h>
#include <kextrw.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  if (kextrw_init() == -1) {
    puts("❌ KextRW init failed");
    return 1;
  }

  uint64_t kbase = get_kernel_base();
  if (!kbase) {
    puts("❌ Couldn’t find kernel base");
    kextrw_deinit();
    return 1;
  }
  printf("🍦 Kernel base: 0x%llx\n", kbase);

  csh handle;
  if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
    puts("❌ Capstone init failed");
    kextrw_deinit();
    return 1;
  }
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

  cs_close(&handle);
  kextrw_deinit();

  return 0;
}
