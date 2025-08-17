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
#define ANSI_INTENSE_BLACK     "\x1b[90m"
#define ANSI_INTENSE_RED       "\x1b[91m"
#define ANSI_INTENSE_GREEN     "\x1b[92m"
#define ANSI_INTENSE_YELLOW    "\x1b[93m"
#define ANSI_INTENSE_BLUE      "\x1b[94m"
#define ANSI_INTENSE_MAGENTA   "\x1b[95m"
#define ANSI_INTENSE_CYAN      "\x1b[96m"
#define ANSI_INTENSE_WHITE     "\x1b[97m"

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
//  Decorations + Colors
// =======================
#define ANSI_BOLD_BLACK    "\x1b[1;30m"
#define ANSI_BOLD_RED      "\x1b[1;31m"
#define ANSI_BOLD_GREEN    "\x1b[1;32m"
#define ANSI_BOLD_YELLOW   "\x1b[1;33m"
#define ANSI_BOLD_BLUE     "\x1b[1;34m"
#define ANSI_BOLD_MAGENTA  "\x1b[1;35m"
#define ANSI_BOLD_CYAN     "\x1b[1;36m"
#define ANSI_BOLD_WHITE    "\x1b[1;37m"

#define ANSI_UNDERLINE_BLACK   "\x1b[4;30m"
#define ANSI_UNDERLINE_RED     "\x1b[4;31m"
#define ANSI_UNDERLINE_GREEN   "\x1b[4;32m"
#define ANSI_UNDERLINE_YELLOW  "\x1b[4;33m"
#define ANSI_UNDERLINE_BLUE    "\x1b[4;34m"
#define ANSI_UNDERLINE_MAGENTA "\x1b[4;35m"
#define ANSI_UNDERLINE_CYAN    "\x1b[4;36m"
#define ANSI_UNDERLINE_WHITE   "\x1b[4;37m"

// ========================
//  Extended Color Support (256-color palette)
// ========================
#define ANSI_FG_256(n) "\x1b[38;5;" #n "m"
#define ANSI_BG_256(n) "\x1b[48;5;" #n "m"
#define ANSI_FG_RGB(r,g,b) "\x1b[38;2;" #r ";" #g ";" #b "m"
#define ANSI_BG_RGB(r,g,b) "\x1b[48;2;" #r ";" #g ";" #b "m"

// ======================
//  Cursor Controls
// ======================
#define ANSI_CURSOR_HOME     "\x1b[H"
#define ANSI_CURSOR_MOVE(row,col) "\x1b[" #row ";" #col "H"
#define ANSI_CURSOR_SAVE     "\x1b[s"
#define ANSI_CURSOR_RESTORE  "\x1b[u"
#define ANSI_CURSOR_HIDE     "\x1b[?25l"
#define ANSI_CURSOR_SHOW     "\x1b[?25h"

// ======================
//  Screen Controls
// ======================
#define ANSI_CLEAR_SCREEN    "\x1b[2J"
#define ANSI_CLEAR_LINE      "\x1b[2K"

#endif 
