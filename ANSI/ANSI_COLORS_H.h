#ifndef ANSI_COLORS_H
#define ANSI_COLORS_H

// =====================
//  Basic Colors (30–37)
// =====================
#define ANSI_BLACK         "\x1b[30m"
#define ANSI_RED           "\x1b[31m"
#define ANSI_GREEN         "\x1b[32m"
#define ANSI_YELLOW        "\x1b[33m"
#define ANSI_BLUE          "\x1b[34m"
#define ANSI_MAGENTA       "\x1b[35m"
#define ANSI_CYAN          "\x1b[36m"
#define ANSI_WHITE         "\x1b[37m"

// ===========================
//  Bright Colors (90–97)
// ===========================
#define ANSI_BOLD_BLACK    "\x1b[90m"
#define ANSI_BOLD_RED       "\x1b[91m"
#define ANSI_BOLD_GREEN     "\x1b[92m"
#define ANSI_BOLD_YELLOW    "\x1b[93m"
#define ANSI_BOLD_BLUE      "\x1b[94m"
#define ANSI_BOLD_MAGENTA   "\x1b[95m"
#define ANSI_BOLD_CYAN      "\x1b[96m"
#define ANSI_BOLD_WHITE     "\x1b[97m"

// ======================
//  Background Colors
// ======================
#define ANSI_BG_BLACK     "\x1b[40m"
#define ANSI_BG_RED       "\x1b[41m"
#define ANSI_BG_GREEN     "\x1b[42m"
#define ANSI_BG_YELLOW    "\x1b[43m"
#define ANSI_BG_BLUE      "\x1b[44m"
#define ANSI_BG_MAGENTA   "\x1b[45m"
#define ANSI_BG_CYAN      "\x1b[46m"
#define ANSI_BG_WHITE     "\x1b[47m"

// ======================
// Bright Background Colors
// ======================
#define ANSI_BG_INTENSE_BLACK     "\x1b[100m"
#define ANSI_BG_INTENSE_RED       "\x1b[101m"
#define ANSI_BG_INTENSE_GREEN     "\x1b[102m"
#define ANSI_BG_INTENSE_YELLOW    "\x1b[103m"
#define ANSI_BG_INTENSE_BLUE      "\x1b[104m"
#define ANSI_BG_INTENSE_MAGENTA   "\x1b[105m"
#define ANSI_BG_INTENSE_CYAN      "\x1b[106m"
#define ANSI_BG_INTENSE_WHITE     "\x1b[107m"

// ======================
//  Text Attributes
// ======================
#define ANSI_RESET         "\x1b[0m"
#define ANSI_BOLD          "\x1b[1m"
#define ANSI_DIM           "\x1b[2m"
#define ANSI_ITALIC        "\x1b[3m"
#define ANSI_UNDERLINE     "\x1b[4m"
#define ANSI_DOUBLE_UNDERLINE "\x1b[21m"
#define ANSI_REVERSE       "\x1b[7m"
#define ANSI_HIDDEN        "\x1b[8m"
#define ANSI_STRIKETHROUGH "\x1b[9m"
#define ANSI_BLINK_SLOW    "\x1b[5m"
#define ANSI_BLINK_FAST    "\x1b[6m"
#define ANSI_FRAMED        "\x1b[51m"
#define ANSI_ENCIRCLED     "\x1b[52m"
#define ANSI_OVERLINED     "\x1b[53m"

// =========================
//  SGR
// =========================
#define ANSI_SUPERSCRIPT       "\x1b[73m"
#define ANSI_SUBSCRIPT         "\x1b[74m"
#define ANSI_IDEOGRAM_UNDERLINE "\x1b[60m"
#define ANSI_IDEOGRAM_DOUBLE_UNDERLINE "\x1b[61m"
#define ANSI_PROPORTIONAL_SPACING "\x1b[90m"
#define ANSI_NO_PROPORTIONAL_SPACING "\x1b[91m"

// =========================
//  Attribute Resets
// =========================
#define ANSI_NORMAL_INTENSITY   "\x1b[22m"
#define ANSI_NO_ITALIC          "\x1b[23m"
#define ANSI_NO_UNDERLINE       "\x1b[24m"
#define ANSI_NO_BLINK           "\x1b[25m"
#define ANSI_NO_REVERSE         "\x1b[27m"
#define ANSI_NO_HIDDEN          "\x1b[28m"
#define ANSI_NO_STRIKETHROUGH   "\x1b[29m"
#define ANSI_NO_FRAMED_ENCIRCLED "\x1b[54m"
#define ANSI_NO_OVERLINED       "\x1b[55m"

// =======================
//  Extended Colors
// =======================
#define ANSI_FG_256(n) "\x1b[38;5;" #n "m"
#define ANSI_BG_256(n) "\x1b[48;5;" #n "m"
#define ANSI_FG_RGB(r,g,b) "\x1b[38;2;" #r ";" #g ";" #b "m"
#define ANSI_BG_RGB(r,g,b) "\x1b[48;2;" #r ";" #g ";" #b "m"

// ======================
//  Cursor Controls
// ======================
#define ANSI_CURSOR_HOME     "\x1b[H"
#define ANSI_CURSOR_MOVE(row,col) "\x1b[" #row ";" #col "H"
#define ANSI_CURSOR_UP(n)   "\x1b[" #n "A"
#define ANSI_CURSOR_DOWN(n) "\x1b[" #n "B"
#define ANSI_CURSOR_FORWARD(n) "\x1b[" #n "C"
#define ANSI_CURSOR_BACK(n) "\x1b[" #n "D"
#define ANSI_CURSOR_SAVE     "\x1b[s"
#define ANSI_CURSOR_RESTORE  "\x1b[u"
#define ANSI_CURSOR_HIDE     "\x1b[?25l"
#define ANSI_CURSOR_SHOW     "\x1b[?25h"
#define ANSI_CURSOR_POS      "\x1b[6n"

// ======================
//  Screen Controls
// ======================
#define ANSI_CLEAR_SCREEN    "\x1b[2J"
#define ANSI_CLEAR_LINE      "\x1b[2K"
#define ANSI_CLEAR_TO_EOL    "\x1b[0K"
#define ANSI_CLEAR_TO_SOL    "\x1b[1K"
#define ANSI_SCROLL_UP(n)    "\x1b[" #n "S"
#define ANSI_SCROLL_DOWN(n)  "\x1b[" #n "T"

// ======================
//  Terminal Mode / OSC / DCS
// ======================
#define ANSI_SAVE_TITLE      "\x1b[22;0t"
#define ANSI_RESTORE_TITLE   "\x1b[23;0t"
#define ANSI_SET_TITLE(title) "\x1b]0;" title "\x07"
#define ANSI_CLIPBOARD_COPY(text) "\x1b]52;c;" text "\x07"
#define ANSI_CLIPBOARD_PASTE "\x1b]52;c;?\x07"
#define ANSI_SET_RGB_FG(r,g,b) "\x1b]10;rgb:" #r "/" #g "/" #b "\x07"
#define ANSI_SET_RGB_BG(r,g,b) "\x1b]11;rgb:" #r "/" #g "/" #b "\x07"
#define ANSI_HYPERLINK(url,text) "\x1b]8;;" url "\x07" text "\x1b]8;;\x07"

// ======================
//  Mouse Reporting
// ======================
#define ANSI_MOUSE_CLICK_ON  "\x1b[?1000h"
#define ANSI_MOUSE_CLICK_OFF "\x1b[?1000l"
#define ANSI_MOUSE_DRAG_ON   "\x1b[?1002h"
#define ANSI_MOUSE_DRAG_OFF  "\x1b[?1002l"
#define ANSI_MOUSE_MOVE_ON   "\x1b[?1003h"
#define ANSI_MOUSE_MOVE_OFF  "\x1b[?1003l"

// ======================
//  Insert/Delete Sequences
// ======================
#define ANSI_INSERT_LINE(n)    "\x1b[" #n "L"
#define ANSI_DELETE_LINE(n)    "\x1b[" #n "M"
#define ANSI_INSERT_CHAR(n)    "\x1b[" #n "@"
#define ANSI_DELETE_CHAR(n)    "\x1b[" #n "P"

// ======================
//  Other
// ======================
#define ANSI_BELL            "\x07"
#define ANSI_SOFT_RESET      "\x1b[!p"       // DECSTR
#define ANSI_HARD_RESET      "\x1b[!p"       // often same as soft on modern terminals
#define ANSI_ALTERNATE_BUFFER "\x1b[?1049h"
#define ANSI_MAIN_BUFFER      "\x1b[?1049l"
#define ANSI_WRAP_ON         "\x1b[?7h"
#define ANSI_WRAP_OFF        "\x1b[?7l"
#define ANSI_MOUSE_REPORTING_EXT "\x1b[?1015h" // URXVT style

#endif
