#define MATE_IMPLEMENTATION
#include "mate.h"

i32 main(void) {
  StartBuild();
  {
    if (!isMacOs()) {
      printf("Error: This build script is intended for macOS only.\n");
      return 1;
    }

    Executable executable = CreateExecutable(
        (ExecutableOptions){.output = "kinspect",
                            .flags = "-Wall -Wextra",
                            .linkerFlags = "-lkextrw -lcapstone"});

    AddIncludePaths(executable, "/usr/local/include",
                    "/opt/homebrew/Cellar/capstone/5.0.5/include/capstone");
    AddLibraryPaths(executable, "/usr/local/lib",
                    "/opt/homebrew/Cellar/capstone/5.0.5/lib");

    // Link frameworks properly
    LinkFrameworks(executable, "IOKit", "CoreFoundation");

    // Add source files
    AddFile(executable, "./src/*.c");

    InstallExecutable(executable);
  }
  EndBuild();
}
