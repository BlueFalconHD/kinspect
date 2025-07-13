#include "Logging.h"
#include "Terminal.h"
#include <stdarg.h>

#define DEFAULT_LOG_CONFIG_INCLUDE_TIMESTAMPS false
#define DEFAULT_LOG_CONFIG_INCLUDE_LOG_LEVELS true
#define DEFAULT_LOG_CONFIG_INCLUDE_LOGGER_NAME false
#define DEFAULT_LOG_CONFIG_LOG_LEVEL LOG_LEVEL_DEBUG

// Color mapping for different log levels
static const char *getLogLevelColor(LogLevel level) {
  if (!TerminalSupportsFormatting()) {
    return "";
  }

  switch (level) {
  case LOG_LEVEL_FATAL:
    return aBOLD afBRIGHT_RED;
  case LOG_LEVEL_ERROR:
    return afRED;
  case LOG_LEVEL_WARNING:
    return afYELLOW;
  case LOG_LEVEL_INFO:
    return afGREEN;
  case LOG_LEVEL_DEBUG:
    return afBLUE;
  default:
    return "";
  }
}

// String representation of log levels
static const char *getLogLevelString(LogLevel level) {
  switch (level) {
  case LOG_LEVEL_FATAL:
    return "FATAL";
  case LOG_LEVEL_ERROR:
    return "ERROR";
  case LOG_LEVEL_WARNING:
    return "WARN";
  case LOG_LEVEL_INFO:
    return "INFO";
  case LOG_LEVEL_DEBUG:
    return "DEBUG";
  default:
    return "UNK";
  }
}

Logger *createLogger(LoggerConfig config) {
  Logger *logger = (Logger *)malloc(sizeof(Logger));
  if (!logger) {
    fprintf(stderr, "Failed to allocate memory for logger\n");
    return NULL;
  }

  logger->config = config;

  // Set default streams if not provided
  if (!logger->config.outputStream) {
    logger->config.outputStream = stdout;
  }
  if (!logger->config.errorStream) {
    logger->config.errorStream = stderr;
  }

  return logger;
}

Logger *createDefaultLogger(const char *name) {
  LoggerConfig config = {
      .name = name,
      .outputStream = stdout,
      .errorStream = stderr,
      .includeTimestamps = DEFAULT_LOG_CONFIG_INCLUDE_TIMESTAMPS,
      .includeLogLevels = DEFAULT_LOG_CONFIG_INCLUDE_LOG_LEVELS,
      .includeLoggerName = DEFAULT_LOG_CONFIG_INCLUDE_LOGGER_NAME,
      .logLevel = DEFAULT_LOG_CONFIG_LOG_LEVEL};

  return createLogger(config);
}

void logMessage(Logger *logger, LogLevel level, const char *format, ...) {
  if (!logger)
    return;

  // Check if the message should be logged based on the minimum log level
  if (level > logger->config.logLevel) {
    return;
  }

  // Select the appropriate output stream
  FILE *stream = (level <= LOG_LEVEL_ERROR) ? logger->config.errorStream
                                            : logger->config.outputStream;

  // Prepare timestamp if needed
  char timestamp[24] = {0};
  if (logger->config.includeTimestamps) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S ", tm_info);
  }

  // Get color for the log level
  const char *levelColor = getLogLevelColor(level);
  const char *resetColor = TerminalSupportsFormatting() ? aRESET : "";

  // Start building the log message - following the order: timestamp, logger
  // name, log level
  if (logger->config.includeTimestamps) {
    fprintf(stream, "%s", timestamp);
  }

  // Include logger name if configured
  if (logger->config.includeLoggerName && logger->config.name) {
    fprintf(stream, "(%s) ", logger->config.name);
  }

  // Include log level if configured - with alignment
  if (logger->config.includeLogLevels) {
    // Get log level string
    const char *levelString = getLogLevelString(level);

    // Add padding for alignment (INFO and WARN need an extra space to align
    // with DEBUG and ERROR, FATAL needs none)
    char padding[2] = {0};
    if (strcmp(levelString, "INFO") == 0 || strcmp(levelString, "WARN") == 0) {
      padding[0] = ' ';
    }

    fprintf(stream, "[%s%s%s]%s ", levelColor, levelString, resetColor,
            padding);
  }

  // Print the actual message
  va_list args;
  va_start(args, format);
  vfprintf(stream, format, args);
  va_end(args);

  // Add a newline if the format doesn't end with one
  if (format[0] != '\0' && format[strlen(format) - 1] != '\n') {
    fprintf(stream, "\n");
  }

  // Flush the stream to ensure the message is output immediately
  fflush(stream);

  // For fatal errors, terminate the program
  if (level == LOG_LEVEL_FATAL) {
    fprintf(stream, "%sProgram terminated due to fatal error.%s\n", levelColor,
            resetColor);
    exit(EXIT_FAILURE);
  }
}

void logFatal(Logger *logger, const char *format, ...) {
  if (!logger)
    return;

  va_list args;
  va_start(args, format);

  // Copy the format string and arguments
  char buffer[4096]; // Large buffer for the formatted message
  vsnprintf(buffer, sizeof(buffer), format, args);

  logMessage(logger, LOG_LEVEL_FATAL, "%s", buffer);

  va_end(args);

  // logFatal should never return as logMessage will exit the program
}

void logError(Logger *logger, const char *format, ...) {
  if (!logger)
    return;

  va_list args;
  va_start(args, format);

  char buffer[4096];
  vsnprintf(buffer, sizeof(buffer), format, args);

  logMessage(logger, LOG_LEVEL_ERROR, "%s", buffer);

  va_end(args);
}

void logWarning(Logger *logger, const char *format, ...) {
  if (!logger)
    return;

  va_list args;
  va_start(args, format);

  char buffer[4096];
  vsnprintf(buffer, sizeof(buffer), format, args);

  logMessage(logger, LOG_LEVEL_WARNING, "%s", buffer);

  va_end(args);
}

void logInfo(Logger *logger, const char *format, ...) {
  if (!logger)
    return;

  va_list args;
  va_start(args, format);

  char buffer[4096];
  vsnprintf(buffer, sizeof(buffer), format, args);

  logMessage(logger, LOG_LEVEL_INFO, "%s", buffer);

  va_end(args);
}

void logDebug(Logger *logger, const char *format, ...) {
  if (!logger)
    return;

  va_list args;
  va_start(args, format);

  char buffer[4096];
  vsnprintf(buffer, sizeof(buffer), format, args);

  logMessage(logger, LOG_LEVEL_DEBUG, "%s", buffer);

  va_end(args);
}

void destroyLogger(Logger *logger) {
  if (!logger)
    return;

  // No need to close stdout/stderr as they're managed by the system

  // Free the logger itself
  free(logger);
}
