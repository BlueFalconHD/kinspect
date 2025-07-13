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

    StringBuilder ldidStringBuilder = StringBuilderCreate(mateState.arena);
    StringBuilderAppend(mateState.arena, &ldidStringBuilder,
                        &S("ldid -Sentitlements.plist "));
    StringBuilderAppend(mateState.arena, &ldidStringBuilder,
                        &executable.outputPath);

    errno_t ldidRes = RunCommand(ldidStringBuilder.buffer);
    if (ldidRes != 0) {
      printf("Error running ldid: %s\n", strerror(ldidRes));
      return 1;
    }

    CreateCompileCommandsError cc = CreateCompileCommands(executable);
    if (cc != COMPILE_COMMANDS_SUCCESS) {
      printf("Error creating compile commands: %d\n", cc);
      return 1;
    }
  }
  EndBuild();
}
