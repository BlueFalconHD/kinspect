#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <termios.h>
#include <unistd.h>

#define MAX_LINE_LENGTH 1024
#define MAX_LINES 1000

typedef struct {
    char *content;
    size_t length;
    size_t capacity;
} EditorLine;

typedef struct {
    int line;
    int column;
} CursorPosition;

typedef struct {
    EditorLine *lines;
    int num_lines;
    int max_lines;
    CursorPosition cursor;
    int scroll_offset;
    struct termios original_termios;
    bool raw_mode_enabled;
} TextEditor;

/**
 * Creates and initializes a new text editor.
 *
 * @return A pointer to the created TextEditor instance, or NULL on failure.
 */
TextEditor *createTextEditor(void);

/**
 * Runs the text editor main loop.
 *
 * @param editor The text editor instance.
 * @return The final buffer content as a string, or NULL on error.
 */
char *runTextEditor(TextEditor *editor);

/**
 * Destroys the text editor and frees associated resources.
 *
 * @param editor The text editor instance to destroy.
 */
void destroyTextEditor(TextEditor *editor);

/**
 * Enables raw mode for the terminal.
 *
 * @param editor The text editor instance.
 * @return true on success, false on failure.
 */
bool enableRawMode(TextEditor *editor);

/**
 * Disables raw mode and restores original terminal settings.
 *
 * @param editor The text editor instance.
 */
void disableRawMode(TextEditor *editor);

/**
 * Renders the entire editor to the terminal.
 *
 * @param editor The text editor instance.
 */
void renderEditor(TextEditor *editor);

/**
 * Processes a single character input.
 *
 * @param editor The text editor instance.
 * @param c The character to process.
 * @return true to continue editing, false to exit.
 */
bool processInput(TextEditor *editor, char c);

/**
 * Inserts a character at the current cursor position.
 *
 * @param editor The text editor instance.
 * @param c The character to insert.
 */
void insertChar(TextEditor *editor, char c);

/**
 * Deletes the character to the left of the cursor.
 *
 * @param editor The text editor instance.
 */
void deleteChar(TextEditor *editor);

/**
 * Inserts a new line at the current cursor position.
 *
 * @param editor The text editor instance.
 */
void insertNewline(TextEditor *editor);

/**
 * Moves the cursor in the specified direction.
 *
 * @param editor The text editor instance.
 * @param direction The direction to move (up, down, left, right).
 */
void moveCursor(TextEditor *editor, char direction);

/**
 * Gets the final buffer content as a single string.
 *
 * @param editor The text editor instance.
 * @return The buffer content as a string, or NULL on error.
 */
char *getEditorBuffer(TextEditor *editor);

/**
 * Triggers a terminal bell.
 */
void triggerBell(void);

/**
 * Hides the cursor in the terminal
 */
void hideCursor(void);

/**
 * Shows the cursor in the terminal
 */
void showCursor(void);
