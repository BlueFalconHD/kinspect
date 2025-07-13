#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

/*
 * Log levels for the logger.
 * These levels determine the severity of the log messages.
 */
typedef enum {
    LOG_LEVEL_FATAL = 0,
    LOG_LEVEL_ERROR = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_INFO = 3,
    LOG_LEVEL_DEBUG = 4
} LogLevel;

typedef struct {
    // name of the logger (shown in log messages)
    const char *name;

    // file descriptors for the output and error streams
    FILE *outputStream;
    FILE *errorStream;

    // whether to include timestamps in the log messages
    bool includeTimestamps;

    // whether to include log levels in the log messages
    bool includeLogLevels;

    // whether to include the logger name in the log messages
    bool includeLoggerName;

    // the minimum log level to log messages (messages below this level will be ignored)
    // A value of LOG_LEVEL_DEBUG means all messages will be logged, while a value of LOG_LEVEL_FATAL means nothing except fatal errors will be logged.
    LogLevel logLevel;
} LoggerConfig;

/**
 * Logs messages to the configured output stream.
 */
typedef struct {
    LoggerConfig config;
} Logger;

/**
 * Creates a new logger with the specified configuration.
 *
 * @param config The configuration for the logger.
 * @return A pointer to the created Logger instance.
 */
Logger *createLogger(LoggerConfig config);

/**
 * Creates a new logger with default configuration that outputs to stdout/stderr.
 *
 * Default configuration includes:
 * - Logger name as provided
 * - Output to stdout for non-error messages
 * - Output to stderr for error messages
 * - Timestamps enabled
 * - Log levels enabled
 * - Logger name included in messages
 * - Minimum log level set to LOG_LEVEL_INFO
 *
 * @param name The name for the logger.
 * @return A pointer to the created Logger instance with default settings.
 */
Logger *createDefaultLogger(const char *name);

/**
 * Logs a message with the specified log level.
 *
 * @param logger The logger to use for logging.
 * @param level The log level of the message.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logMessage(Logger *logger, LogLevel level, const char *format, ...);

// Convenience functions for logging at different levels

/**
 * Logs a fatal error message and terminates the program.
 *
 * @param logger The logger to use for logging.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logFatal(Logger *logger, const char *format, ...);

/**
 * Logs an error message.
 *
 * @param logger The logger to use for logging.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logError(Logger *logger, const char *format, ...);

/**
 * Logs a warning message.
 *
 * @param logger The logger to use for logging.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logWarning(Logger *logger, const char *format, ...);

/**
 * Logs an informational message.
 *
 * @param logger The logger to use for logging.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logInfo(Logger *logger, const char *format, ...);

/**
 * Logs a debug message.
 *
 * @param logger The logger to use for logging.
 * @param format The format string for the message.
 * @param ... Additional arguments for the format string.
 */
void logDebug(Logger *logger, const char *format, ...);

/**
 * Destroys the logger and frees any associated resources.
 *
 * @param logger The logger to destroy.
 */
void destroyLogger(Logger *logger);
