#include "Input.h"
#include "Terminal.h"
#include <ctype.h>
#include <sys/ioctl.h>

#define CTRL_KEY(k) ((k) & 0x1f)
#define ESCAPE_SEQ_START 27

static int getTerminalSize(int *rows, int *cols) {
  struct winsize ws;
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
    return -1;
  }
  *rows = ws.ws_row;
  *cols = ws.ws_col;
  return 0;
}

static int getLineNumberWidth(int num_lines) {
  int width = 1;
  int temp = num_lines;
  while (temp >= 10) {
    width++;
    temp /= 10;
  }
  return width;
}

void hideCursor() {
  if (TerminalSupportsFormatting()) {
    printf(aHIDE_CURSOR);
  }
}

void showCursor() {
  if (TerminalSupportsFormatting()) {
    printf(aSHOW_CURSOR);
  }
}

TextEditor *createTextEditor(void) {
  TextEditor *editor = malloc(sizeof(TextEditor));
  if (!editor) {
    return NULL;
  }

  editor->lines = malloc(sizeof(EditorLine) * MAX_LINES);
  if (!editor->lines) {
    free(editor);
    return NULL;
  }

  // Initialize first line
  editor->lines[0].content = malloc(MAX_LINE_LENGTH);
  if (!editor->lines[0].content) {
    free(editor->lines);
    free(editor);
    return NULL;
  }
  editor->lines[0].content[0] = '\0';
  editor->lines[0].length = 0;
  editor->lines[0].capacity = MAX_LINE_LENGTH;

  editor->num_lines = 1;
  editor->max_lines = MAX_LINES;
  editor->cursor.line = 0;
  editor->cursor.column = 0;
  editor->scroll_offset = 0;
  editor->raw_mode_enabled = false;

  return editor;
}

void destroyTextEditor(TextEditor *editor) {
  if (!editor)
    return;

  if (editor->raw_mode_enabled) {
    disableRawMode(editor);
  }

  for (int i = 0; i < editor->num_lines; i++) {
    free(editor->lines[i].content);
  }
  free(editor->lines);
  free(editor);
}

bool enableRawMode(TextEditor *editor) {
  if (tcgetattr(STDIN_FILENO, &editor->original_termios) == -1) {
    return false;
  }

  struct termios raw = editor->original_termios;
  raw.c_iflag &= ~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
  raw.c_oflag &= ~(OPOST);
  raw.c_cflag |= (CS8);
  raw.c_lflag &= ~(ECHO | ICANON | IEXTEN | ISIG);
  raw.c_cc[VMIN] = 1;
  raw.c_cc[VTIME] = 0;

  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) == -1) {
    return false;
  }

  editor->raw_mode_enabled = true;
  return true;
}

void disableRawMode(TextEditor *editor) {
  if (editor->raw_mode_enabled) {
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &editor->original_termios);
    editor->raw_mode_enabled = false;
  }
}

static int last_rendered_lines = 0;

static void ensureCursorVisible(TextEditor *editor) {
  int terminal_rows, terminal_cols;
  if (getTerminalSize(&terminal_rows, &terminal_cols) == -1) {
    terminal_rows = 24; // fallback
  }

  // Calculate maximum scroll offset
  int max_scroll = (editor->num_lines > terminal_rows)
                       ? editor->num_lines - terminal_rows
                       : 0;

  // Clamp scroll_offset to valid range first
  if (editor->scroll_offset < 0) {
    editor->scroll_offset = 0;
  }
  if (editor->scroll_offset > max_scroll) {
    editor->scroll_offset = max_scroll;
  }

  // Adjust scroll offset to keep cursor visible
  if (editor->cursor.line < editor->scroll_offset) {
    // Cursor is above visible area, scroll up
    editor->scroll_offset = editor->cursor.line;
  } else if (editor->cursor.line >= editor->scroll_offset + terminal_rows) {
    // Cursor is below visible area, scroll down
    editor->scroll_offset = editor->cursor.line - terminal_rows + 1;
    // Ensure we don't exceed maximum scroll
    if (editor->scroll_offset > max_scroll) {
      editor->scroll_offset = max_scroll;
    }
  }

  // Final bounds check to be extra safe
  if (editor->scroll_offset < 0) {
    editor->scroll_offset = 0;
  }
  if (editor->scroll_offset > max_scroll) {
    editor->scroll_offset = max_scroll;
  }
}

void renderEditor(TextEditor *editor) {
  int terminal_rows, terminal_cols;
  if (getTerminalSize(&terminal_rows, &terminal_cols) == -1) {
    terminal_rows = 24; // fallback
  }

  // Ensure cursor is visible before rendering
  ensureCursorVisible(editor);

  int visible_lines = terminal_rows;
  int start_line = editor->scroll_offset;
  int end_line = start_line + visible_lines;
  if (end_line > editor->num_lines) {
    end_line = editor->num_lines;
  }

  if (last_rendered_lines > 0) {
    printf("\033[%dA", last_rendered_lines); // Move cursor up
  }

  hideCursor();

  int line_num_width = getLineNumberWidth(editor->num_lines);
  int rendered_lines = 0;

  for (int i = start_line; i < end_line; i++) {
    printf("\r"); // Always start from beginning of line
    if (rendered_lines < last_rendered_lines) {
      printf(aCLEAR_LINE);
    }

    // print aligned line number
    printf("%*d:", line_num_width, i + 1);

    EditorLine *line = &editor->lines[i];

    // Print line content with cursor highlighting
    for (int j = 0; j < (int)line->length; j++) {
      if (i == editor->cursor.line && j == editor->cursor.column) {
        printf(aREVERSE "%c" aRESET, line->content[j]);
      } else {
        printf("%c", line->content[j]);
      }
    }

    // Show cursor at end of line if that's where it is
    if (i == editor->cursor.line &&
        editor->cursor.column == (int)line->length) {
      printf(aREVERSE " " aRESET);
    }

    printf("\n");
    rendered_lines++;
  }

  // clear any extra lines if we rendered fewer than the last time
  for (int i = rendered_lines; i < last_rendered_lines; i++) {
    printf("\r" aCLEAR_LINE "\n");
  }

  // move cursor to the correct position
  if (last_rendered_lines > rendered_lines) {
    printf("\033[%dA", last_rendered_lines - rendered_lines);
  }

  last_rendered_lines = rendered_lines;
  fflush(stdout);
}

void triggerBell(void) {
  printf("\a");
  fflush(stdout);
}

void moveCursor(TextEditor *editor, char direction) {
  switch (direction) {
  case 'h': // Left
    if (editor->cursor.column > 0) {
      editor->cursor.column--;
    } else if (editor->cursor.line > 0) {
      editor->cursor.line--;
      editor->cursor.column = editor->lines[editor->cursor.line].length;
    } else {
      triggerBell();
    }
    break;

  case 'l': // Right
    if (editor->cursor.column <
        (int)editor->lines[editor->cursor.line].length) {
      editor->cursor.column++;
    } else if (editor->cursor.line < editor->num_lines - 1) {
      editor->cursor.line++;
      editor->cursor.column = 0;
    } else {
      triggerBell();
    }
    break;

  case 'k': // Up
    if (editor->cursor.line > 0) {
      editor->cursor.line--;
      int max_col = editor->lines[editor->cursor.line].length;
      if (editor->cursor.column > max_col) {
        editor->cursor.column = max_col;
      }
    } else {
      triggerBell();
    }
    break;

  case 'j': // Down
    if (editor->cursor.line < editor->num_lines - 1) {
      editor->cursor.line++;
      int max_col = editor->lines[editor->cursor.line].length;
      if (editor->cursor.column > max_col) {
        editor->cursor.column = max_col;
      }
    } else {
      triggerBell();
    }
    break;
  }

  ensureCursorVisible(editor);
}

void insertChar(TextEditor *editor, char c) {
  EditorLine *line = &editor->lines[editor->cursor.line];

  if (line->length >= line->capacity - 1) {
    return; // full line, cannot insert character
  }

  // shift characters to the right
  for (int i = line->length; i > editor->cursor.column; i--) {
    line->content[i] = line->content[i - 1];
  }

  line->content[editor->cursor.column] = c;
  line->length++;
  line->content[line->length] = '\0';

  editor->cursor.column++;
}

void deleteChar(TextEditor *editor) {
  if (editor->cursor.column == 0 && editor->cursor.line == 0) {
    triggerBell();
    return;
  }

  EditorLine *line = &editor->lines[editor->cursor.line];

  if (editor->cursor.column > 0) {
    // delete character to the left
    for (int i = editor->cursor.column - 1; i < (int)line->length - 1; i++) {
      line->content[i] = line->content[i + 1];
    }
    line->length--;
    line->content[line->length] = '\0';
    editor->cursor.column--;
  } else {
    // delete newline
    if (editor->cursor.line > 0) {
      EditorLine *prev_line = &editor->lines[editor->cursor.line - 1];
      int prev_length = prev_line->length;

      // check if we can merge lines
      if (prev_length + line->length < prev_line->capacity) {
        // merge current line into previous line
        strcpy(prev_line->content + prev_length, line->content);
        prev_line->length += line->length;

        // move cursor to end of previous line
        editor->cursor.line--;
        editor->cursor.column = prev_length;

        // shift lines up
        free(line->content);
        for (int i = editor->cursor.line + 1; i < editor->num_lines - 1; i++) {
          editor->lines[i] = editor->lines[i + 1];
        }
        editor->num_lines--;

        ensureCursorVisible(editor);
      } else {
        triggerBell();
      }
    }
  }
}

void insertNewline(TextEditor *editor) {
  if (editor->num_lines >= editor->max_lines) {
    triggerBell();
    return;
  }

  EditorLine *current_line = &editor->lines[editor->cursor.line];

  // shift lines down
  for (int i = editor->num_lines; i > editor->cursor.line + 1; i--) {
    editor->lines[i] = editor->lines[i - 1];
  }

  // create new line
  editor->lines[editor->cursor.line + 1].content = malloc(MAX_LINE_LENGTH);
  if (!editor->lines[editor->cursor.line + 1].content) {
    triggerBell();
    return;
  }
  editor->lines[editor->cursor.line + 1].capacity = MAX_LINE_LENGTH;

  // split current line
  EditorLine *new_line = &editor->lines[editor->cursor.line + 1];
  int split_pos = editor->cursor.column;

  // copy text after cursor to new line
  strcpy(new_line->content, current_line->content + split_pos);
  new_line->length = current_line->length - split_pos;

  // truncate current line
  current_line->content[split_pos] = '\0';
  current_line->length = split_pos;

  editor->num_lines++;
  editor->cursor.line++;
  editor->cursor.column = 0;

  ensureCursorVisible(editor);
}

bool processInput(TextEditor *editor, char c) {
  switch (c) {
  case CTRL_KEY('q'): {
    showCursor();
    return false;
  }

  case '\r':
  case '\n':
    insertNewline(editor);
    break;

  case 127:  // DEL
  case '\b': // Backspace
    deleteChar(editor);
    break;

  case ESCAPE_SEQ_START:
    // handle escape sequences (arrow keys)
    {
      char seq[3];
      if (read(STDIN_FILENO, &seq[0], 1) != 1)
        return true;
      if (read(STDIN_FILENO, &seq[1], 1) != 1)
        return true;

      if (seq[0] == '[') {
        switch (seq[1]) {
        case 'A':
          moveCursor(editor, 'k');
          break; // Up
        case 'B':
          moveCursor(editor, 'j');
          break; // Down
        case 'C':
          moveCursor(editor, 'l');
          break; // Right
        case 'D':
          moveCursor(editor, 'h');
          break; // Left
        }
      }
    }
    break;

  default:
    if (isprint(c)) {
      insertChar(editor, c);
    }
    break;
  }

  return true;
}

char *getEditorBuffer(TextEditor *editor) {
  // calculate total buffer size needed
  size_t total_size = 1; // For null terminator
  for (int i = 0; i < editor->num_lines; i++) {
    total_size += editor->lines[i].length;
    if (i < editor->num_lines - 1) {
      total_size++; // For newline
    }
  }

  char *buffer = malloc(total_size);
  if (!buffer) {
    return NULL;
  }

  buffer[0] = '\0';
  for (int i = 0; i < editor->num_lines; i++) {
    strcat(buffer, editor->lines[i].content);
    if (i < editor->num_lines - 1) {
      strcat(buffer, "\n");
    }
  }

  return buffer;
}

char *runTextEditor(TextEditor *editor) {
  if (!editor) {
    return NULL;
  }

  if (!enableRawMode(editor)) {
    return NULL;
  }

  renderEditor(editor);

  char c;
  while (read(STDIN_FILENO, &c, 1) == 1) {
    if (!processInput(editor, c)) {
      break;
    }
    renderEditor(editor);
  }

  disableRawMode(editor);
  printf("\n"); // Just add a newline to separate from editor

  return getEditorBuffer(editor);
}
