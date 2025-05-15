package main

import (
	"bytes"
	"strings"
	"sync"
	"unicode"

	"github.com/Azure/go-ansiterm"
)

// ScreenCell represents a single cell on the terminal screen
type ScreenCell struct {
	Char    rune
	FgColor int
	BgColor int
	Bold    bool
	// Future attributes: Underline, Inverse, etc.
}

// SGR codes (subset)
const (
	sgrResetAttribute = 0
	sgrBold           = 1
	sgrNoBold         = 22
	// Foreground colors
	sgrFgBlack   = 30
	sgrFgRed     = 31
	sgrFgGreen   = 32
	sgrFgYellow  = 33
	sgrFgBlue    = 34
	sgrFgMagenta = 35
	sgrFgCyan    = 36
	sgrFgWhite   = 37
	sgrFgDefault = 39
	// Background colors
	sgrBgBlack   = 40
	sgrBgRed     = 41
	sgrBgGreen   = 42
	sgrBgYellow  = 43
	sgrBgBlue    = 44
	sgrBgMagenta = 45
	sgrBgCyan    = 46
	sgrBgWhite   = 47
	sgrBgDefault = 49
	// Bright foreground colors
	sgrFgBrightBlack   = 90
	sgrFgBrightRed     = 91
	sgrFgBrightGreen   = 92
	sgrFgBrightYellow  = 93
	sgrFgBrightBlue    = 94
	sgrFgBrightMagenta = 95
	sgrFgBrightCyan    = 96
	sgrFgBrightWhite   = 97
	// Bright background colors
	sgrBgBrightBlack   = 100
	sgrBgBrightRed     = 101
	sgrBgBrightGreen   = 102
	sgrBgBrightYellow  = 103
	sgrBgBrightBlue    = 104
	sgrBgBrightMagenta = 105
	sgrBgBrightCyan    = 106
	sgrBgBrightWhite   = 107
)

// TermEventHandler implements ansiterm.AnsiEventHandler
type TermEventHandler struct {
	mu sync.Mutex

	screen   [][]ScreenCell
	cursorX  int
	cursorY  int
	savedX   int
	savedY   int
	rows     int
	cols     int

	// Current graphic rendition attributes
	currentFgColor int
	currentBgColor int
	currentBold    bool

	scrollTop    int // 0-indexed
	scrollBottom int // 0-indexed

	// For /keystroke_sync line capture
	// These mirror the global variables' purpose but are managed by the event handler
	lineBufferForCapture bytes.Buffer
	capturedLinesForSync []string
}

// NewTermEventHandler creates a new terminal event handler
func NewTermEventHandler(rows, cols int) *TermEventHandler {
	h := &TermEventHandler{
		rows:           rows,
		cols:           cols,
		cursorX:        0,
		cursorY:        0,
		savedX:         0,
		savedY:         0,
		currentFgColor: sgrFgDefault,
		currentBgColor: sgrBgDefault,
		currentBold:    false,
		scrollTop:      0,
		scrollBottom:   rows - 1,
	}

	h.screen = make([][]ScreenCell, rows)
	for i := range h.screen {
		h.screen[i] = make([]ScreenCell, cols)
		for j := range h.screen[i] {
			h.screen[i][j] = ScreenCell{
				Char:    ' ',
				FgColor: h.currentFgColor,
				BgColor: h.currentBgColor,
				Bold:    h.currentBold,
			}
		}
	}
	return h
}

func (h *TermEventHandler) currentCell() ScreenCell {
	return ScreenCell{
		Char:    ' ', // Default to space for clearing
		FgColor: h.currentFgColor,
		BgColor: h.currentBgColor,
		Bold:    h.currentBold,
	}
}

func (h *TermEventHandler) clearScreenArea(y1, x1, y2, x2 int) {
	for r := y1; r <= y2; r++ {
		if r < 0 || r >= h.rows {
			continue
		}
		for c := x1; c <= x2; c++ {
			if c < 0 || c >= h.cols {
				continue
			}
			h.screen[r][c] = h.currentCell() // Clear with current background color
		}
	}
}

func (h *TermEventHandler) scrollUp(regionTop, regionBottom, numLines int) {
	if numLines <= 0 {
		return
	}
	for i := 0; i < numLines; i++ {
		for r := regionTop; r < regionBottom; r++ {
			copy(h.screen[r], h.screen[r+1])
		}
		// Clear the last line of the scroll region
		for c := 0; c < h.cols; c++ {
			h.screen[regionBottom][c] = h.currentCell()
		}
	}
}

func (h *TermEventHandler) scrollDown(regionTop, regionBottom, numLines int) {
	if numLines <= 0 {
		return
	}
	for i := 0; i < numLines; i++ {
		for r := regionBottom; r > regionTop; r-- {
			copy(h.screen[r], h.screen[r-1])
		}
		// Clear the first line of the scroll region
		for c := 0; c < h.cols; c++ {
			h.screen[regionTop][c] = h.currentCell()
		}
	}
}

// --- Implement ansiterm.AnsiEventHandler interface ---

// Print processes a printable character
func (h *TermEventHandler) Print(b byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	char := rune(b)

	// Line capture logic for /keystroke_sync
	if char == '\n' {
		// Append current buffer and include the newline
		line := h.lineBufferForCapture.String()
		if line != "" || len(h.capturedLinesForSync) == 0 {
			// Only add empty line if it's the first line (prompt)
			h.capturedLinesForSync = append(h.capturedLinesForSync, line+"\n")
			logDebug("EventHandler LineCapture LF: Appending CBL ('%s') to PLL. New PLL len: %d. Clearing CBL.", line, len(h.capturedLinesForSync))
		}
		h.lineBufferForCapture.Reset()
	} else if char == '\r' {
		// For CR, just reset buffer - we'll capture on LF
		h.lineBufferForCapture.Reset()
		logDebug("EventHandler LineCapture CR: Resetting CBL")
	} else if char == '\b' { // Backspace
		if h.lineBufferForCapture.Len() > 0 {
			oldCBL := h.lineBufferForCapture.String()
			// Simple truncate last byte. Assumes UTF-8 char is single byte or handled by terminal.
			// For robust multi-byte backspace, would need to decode last rune.
			h.lineBufferForCapture.Truncate(h.lineBufferForCapture.Len() - 1)
			logDebug("EventHandler LineCapture BS: CBL was '%s', now '%s'", oldCBL, h.lineBufferForCapture.String())
		}
	} else if unicode.IsPrint(char) { // Check if it's printable
		h.lineBufferForCapture.WriteRune(char)
		logDebug("EventHandler LineCapture CHAR: Adding char '%s' to CBL. CBL now: '%s'", string(char), h.lineBufferForCapture.String())
	}
	// End line capture logic

	if h.cursorX >= h.cols { // Implicit line wrap from previous char
		h.cursorX = 0
		h.cursorY++
		if h.cursorY > h.scrollBottom {
			h.cursorY = h.scrollBottom
			h.scrollUp(h.scrollTop, h.scrollBottom, 1)
		}
	}

	if h.cursorY >= 0 && h.cursorY < h.rows && h.cursorX >= 0 && h.cursorX < h.cols {
		h.screen[h.cursorY][h.cursorX] = ScreenCell{
			Char:    char,
			FgColor: h.currentFgColor,
			BgColor: h.currentBgColor,
			Bold:    h.currentBold,
		}
	}

	h.cursorX++ // Advance cursor

	return nil
}

// Execute processes C0 control characters
func (h *TermEventHandler) Execute(b byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	switch b {
	case ansiterm.ANSI_BEL: // Bell (0x07)
		// No-op for now, could log or trigger something
	case ansiterm.ANSI_BACKSPACE: // Backspace (0x08)
		if h.cursorX > 0 {
			h.cursorX--
		}
		// Note: Some terminals also erase the character at the new position.
		// To emulate this: h.screen[h.cursorY][h.cursorX] = h.currentCell() with Char: ' '
	case ansiterm.ANSI_TAB: // Horizontal Tab (0x09)
		tabStop := 8
		h.cursorX = (h.cursorX/tabStop + 1) * tabStop
		if h.cursorX >= h.cols { // If tab goes beyond line end
			h.cursorX = h.cols - 1 // Move to last column (or wrap, depending on terminal mode)
			// For simplicity, no wrap on HT here.
		}
	case ansiterm.ANSI_LINE_FEED: // Line Feed (LF, 0x0A)
		// —–– BEGIN line‐capture for /keystroke_sync –––—
		// append whatever is in the buffer (if non‐empty or first line) + “\n”
		line := h.lineBufferForCapture.String()
		if line != "" || len(h.capturedLinesForSync) == 0 {
			h.capturedLinesForSync = append(h.capturedLinesForSync, line+"\n")
			logDebug(
				"EventHandler LineCapture LF (Execute): Appending CBL ('%s') to PLL. New PLL len: %d. Clearing CBL.",
				line, len(h.capturedLinesForSync),
			)
		}
		h.lineBufferForCapture.Reset()
		// —–– END line‐capture –––—
		// now do the normal LF behavior
		h.cursorY++
		if h.cursorY > h.scrollBottom {
			h.cursorY = h.scrollBottom
			h.scrollUp(h.scrollTop, h.scrollBottom, 1)
		}
	case ansiterm.ANSI_VERTICAL_TAB: // Vertical Tab (VT, 0x0B) - Treat like LF
		h.cursorY++
		if h.cursorY > h.scrollBottom {
			h.cursorY = h.scrollBottom
			h.scrollUp(h.scrollTop, h.scrollBottom, 1)
		}
	case ansiterm.ANSI_FORM_FEED: // Form Feed (FF, 0x0C) - Treat like LF or clear screen
		// For now, treat as LF. Some terminals clear screen (ED(2)).
		h.cursorY++
		if h.cursorY > h.scrollBottom {
			h.cursorY = h.scrollBottom
			h.scrollUp(h.scrollTop, h.scrollBottom, 1)
		}
	case ansiterm.ANSI_CARRIAGE_RETURN: // Carriage Return (CR, 0x0D)
		// reset the capture buffer (we’ll capture on LF)
		h.lineBufferForCapture.Reset()
		logDebug("EventHandler LineCapture CR (Execute): Resetting CBL")
		// then do the normal CR behavior
		h.cursorX = 0
	// SO, SI (Shift Out/In for character sets) - not handled for simple vt100/ansi
	// Other C0 codes are typically ignored or have specific behaviors not emulated here.
	}
	return nil
}

// CUU moves cursor up
func (h *TermEventHandler) CUU(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorY -= param
	if h.cursorY < h.scrollTop { // Or just < 0 if not respecting scroll region for this
		h.cursorY = h.scrollTop
	}
	if h.cursorY < 0 { h.cursorY = 0} // Ensure within bounds
	return nil
}

// CUD moves cursor down
func (h *TermEventHandler) CUD(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorY += param
	if h.cursorY > h.scrollBottom { // Or just >= h.rows
		h.cursorY = h.scrollBottom
	}
	if h.cursorY >= h.rows {h.cursorY = h.rows -1} // Ensure within bounds
	return nil
}

// CUF moves cursor forward
func (h *TermEventHandler) CUF(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorX += param
	if h.cursorX >= h.cols {
		h.cursorX = h.cols - 1
	}
	return nil
}

// CUB moves cursor backward
func (h *TermEventHandler) CUB(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorX -= param
	if h.cursorX < 0 {
		h.cursorX = 0
	}
	return nil
}

// CNL moves cursor to next line
func (h *TermEventHandler) CNL(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.CUD(param) // Move down N lines
	h.cursorX = 0  // To start of line
	return nil
}

// CPL moves cursor to previous line
func (h *TermEventHandler) CPL(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.CUU(param) // Move up N lines
	h.cursorX = 0  // To start of line
	return nil
}

// CHA moves cursor to absolute horizontal position
func (h *TermEventHandler) CHA(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorX = param - 1 // 1-indexed to 0-indexed
	if h.cursorX < 0 {
		h.cursorX = 0
	}
	if h.cursorX >= h.cols {
		h.cursorX = h.cols - 1
	}
	return nil
}

// VPA moves cursor to absolute vertical position
func (h *TermEventHandler) VPA(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorY = param - 1 // 1-indexed to 0-indexed
	if h.cursorY < 0 {
		h.cursorY = 0
	}
	if h.cursorY >= h.rows {
		h.cursorY = h.rows - 1
	}
	return nil
}

// CUP moves cursor to given row and column
func (h *TermEventHandler) CUP(row, col int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorY = row - 1 // 1-indexed to 0-indexed
	h.cursorX = col - 1 // 1-indexed to 0-indexed

	if h.cursorY < 0 {
		h.cursorY = 0
	}
	if h.cursorY >= h.rows {
		h.cursorY = h.rows - 1
	}
	if h.cursorX < 0 {
		h.cursorX = 0
	}
	if h.cursorX >= h.cols {
		h.cursorX = h.cols - 1
	}
	return nil
}

// HVP is equivalent to CUP
func (h *TermEventHandler) HVP(row, col int) error {
	return h.CUP(row, col)
}

// ED erases display
func (h *TermEventHandler) ED(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch param {
	case 0: // Erase from cursor to end of screen
		// Erase current line from cursor to end
		h.clearScreenArea(h.cursorY, h.cursorX, h.cursorY, h.cols-1)
		// Erase lines below cursor
		if h.cursorY+1 < h.rows {
			h.clearScreenArea(h.cursorY+1, 0, h.rows-1, h.cols-1)
		}
	case 1: // Erase from start of screen to cursor
		// Erase lines above cursor
		if h.cursorY-1 >= 0 {
			h.clearScreenArea(0, 0, h.cursorY-1, h.cols-1)
		}
		// Erase current line from start to cursor
		h.clearScreenArea(h.cursorY, 0, h.cursorY, h.cursorX)
	case 2: // Erase entire screen
		h.clearScreenArea(0, 0, h.rows-1, h.cols-1)
		// Typically, cursor moves to (0,0) after ED(2)
		// h.cursorX, h.cursorY = 0, 0 // Let CUP handle this if shell sends it
	case 3: // Erase entire screen + scrollback (not applicable here)
		h.clearScreenArea(0, 0, h.rows-1, h.cols-1)
		// h.cursorX, h.cursorY = 0, 0
	}
	return nil
}

// EL erases line
func (h *TermEventHandler) EL(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	switch param {
	case 0: // Erase from cursor to end of line
		h.clearScreenArea(h.cursorY, h.cursorX, h.cursorY, h.cols-1)
	case 1: // Erase from start of line to cursor
		h.clearScreenArea(h.cursorY, 0, h.cursorY, h.cursorX)
	case 2: // Erase entire line
		h.clearScreenArea(h.cursorY, 0, h.cursorY, h.cols-1)
	}
	return nil
}

// IL inserts lines
func (h *TermEventHandler) IL(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursorY >= h.scrollTop && h.cursorY <= h.scrollBottom {
		h.scrollDown(h.cursorY, h.scrollBottom, param)
	}
	return nil
}

// DL deletes lines
func (h *TermEventHandler) DL(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursorY >= h.scrollTop && h.cursorY <= h.scrollBottom {
		h.scrollUp(h.cursorY, h.scrollBottom, param)
	}
	return nil
}

// ICH inserts characters
func (h *TermEventHandler) ICH(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursorY < 0 || h.cursorY >= h.rows || h.cursorX < 0 || h.cursorX >= h.cols {
		return nil
	}
	line := h.screen[h.cursorY]
	// Shift characters to the right
	for i := 0; i < param; i++ {
		for c := h.cols - 1; c > h.cursorX; c-- {
			if c-1 >= 0 {
				line[c] = line[c-1]
			}
		}
		// Insert blank char with current attributes
		line[h.cursorX] = h.currentCell()
	}
	return nil
}

// DCH deletes characters
func (h *TermEventHandler) DCH(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cursorY < 0 || h.cursorY >= h.rows || h.cursorX < 0 || h.cursorX >= h.cols {
		return nil
	}
	line := h.screen[h.cursorY]
	// Shift characters to the left
	for i := 0; i < param; i++ {
		for c := h.cursorX; c < h.cols-1; c++ {
			line[c] = line[c+1]
		}
		// Fill end of line with blank char
		line[h.cols-1] = h.currentCell()
	}
	return nil
}

// SGR sets graphic rendition
func (h *TermEventHandler) SGR(params []int) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(params) == 0 { // ESC[m is equivalent to ESC[0m
		params = []int{sgrResetAttribute}
	}

	for _, p := range params {
		switch {
		case p == sgrResetAttribute: // Reset all attributes
			h.currentFgColor = sgrFgDefault
			h.currentBgColor = sgrBgDefault
			h.currentBold = false
		case p == sgrBold:
			h.currentBold = true
		case p == sgrNoBold: // Normal intensity
			h.currentBold = false
		// Foreground colors
		case p >= sgrFgBlack && p <= sgrFgWhite:
			h.currentFgColor = p
		case p == sgrFgDefault:
			h.currentFgColor = sgrFgDefault
		// Background colors
		case p >= sgrBgBlack && p <= sgrBgWhite:
			h.currentBgColor = p
		case p == sgrBgDefault:
			h.currentBgColor = sgrBgDefault
		// Bright foreground colors
		case p >= sgrFgBrightBlack && p <= sgrFgBrightWhite:
			h.currentFgColor = p
		// Bright background colors
		case p >= sgrBgBrightBlack && p <= sgrBgBrightWhite:
			h.currentBgColor = p
			// Add more SGR codes as needed (italic, underline, blink, etc.)
		}
	}
	return nil
}

// SU scrolls up (pan down)
func (h *TermEventHandler) SU(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Scrolls viewport content up, new lines at bottom
	h.scrollUp(h.scrollTop, h.scrollBottom, param)
	return nil
}

// SD scrolls down (pan up)
func (h *TermEventHandler) SD(param int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Scrolls viewport content down, new lines at top
	h.scrollDown(h.scrollTop, h.scrollBottom, param)
	return nil
}

// DA (Device Attributes) - Reply with terminal identity.
// For an emulator, this might involve writing back to the PTY.
// For now, we'll just log it.
func (h *TermEventHandler) DA(params []string) error {
	logDebug("DA received: %v. Not responding.", params)
	// Example response for VT100: "\x1b[?1;2c" (VT100 with AVO)
	// This would require writing to ptyMaster, which event handler doesn't have direct access to.
	return nil
}

// DECSTBM sets top and bottom margins (scroll region)
func (h *TermEventHandler) DECSTBM(top, bottom int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Params are 1-indexed. If 0 or invalid, often defaults.
	// If bottom is 0 or less than top, or > rows, often means full screen.
	newTop := top - 1
	newBottom := bottom - 1

	if newTop < 0 { newTop = 0 }
	if newBottom >= h.rows || newBottom == -1 { newBottom = h.rows -1 } // -1 from param can mean last line

	if newTop >= newBottom { // Invalid region usually resets to full screen
		h.scrollTop = 0
		h.scrollBottom = h.rows - 1
	} else {
		h.scrollTop = newTop
		h.scrollBottom = newBottom
	}
	// ANSI standard: home cursor after DECSTBM
	h.cursorX = 0
	h.cursorY = 0 // Or h.scrollTop, depending on interpretation
	return nil
}

// RI (Reverse Index) moves cursor up one line, scrolling if at top margin.
func (h *TermEventHandler) RI() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorY--
	if h.cursorY < h.scrollTop {
		h.cursorY = h.scrollTop
		h.scrollDown(h.scrollTop, h.scrollBottom, 1)
	}
	return nil
}

// IND (Index) is equivalent to LF.
func (h *TermEventHandler) IND() error {
	return h.Execute(ansiterm.ANSI_LINE_FEED)
}

// DECSC saves cursor position (ANSI.SYS version, not full VTxxx)
func (h *TermEventHandler) DECSC() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.savedX = h.cursorX
	h.savedY = h.cursorY
	// Full DECSC also saves attributes, character sets etc.
	return nil
}

// DECRC restores cursor position
func (h *TermEventHandler) DECRC() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cursorX = h.savedX
	h.cursorY = h.savedY
	// Clamp to bounds, though saved should be valid
	if h.cursorY < 0 { h.cursorY = 0 }
	if h.cursorY >= h.rows { h.cursorY = h.rows - 1 }
	if h.cursorX < 0 { h.cursorX = 0 }
	if h.cursorX >= h.cols { h.cursorX = h.cols - 1 }
	return nil
}

// --- Stubs for other AnsiEventHandler methods ---
func (h *TermEventHandler) DECTCEM(visible bool) error {
	logDebug("DECTCEM (Cursor Show/Hide): %v. Not implemented.", visible)
	return nil
}
func (h *TermEventHandler) DECOM(use132 bool) error {
	logDebug("DECOM (Origin Mode): %v. Not implemented.", use132)
	return nil /* Origin mode affects CUP behavior */
}
func (h *TermEventHandler) DECCOLM(use132 bool) error {
	logDebug("DECCOLM (132 Column Mode): %v. Not implemented.", use132)
	return nil /* Would require changing h.cols and re-init screen */
}

// Flush is called by parser after Parse() finishes.
func (h *TermEventHandler) Flush() error { return nil }


// --- Methods for accessing screen state (used by /screen endpoint) ---

// GetScreenContent returns the screen content as a slice of strings
func (h *TermEventHandler) GetScreenContent() []string {
	h.mu.Lock()
	defer h.mu.Unlock()

	content := make([]string, h.rows)
	var sb strings.Builder
	for r := 0; r < h.rows; r++ {
		sb.Reset()
		for c := 0; c < h.cols; c++ {
			sb.WriteRune(h.screen[r][c].Char)
		}
		content[r] = sb.String()
	}
	return content
}

// GetCursorState returns the current cursor position
func (h *TermEventHandler) GetCursorState() (x, y int, hidden bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Hidden state is not fully tracked by DECTCEM yet.
	return h.cursorX, h.cursorY, false
}

// GetCapturedLinesAndCurrentBuffer returns data for /keystroke_sync
func (h *TermEventHandler) GetCapturedLinesAndCurrentBuffer() ([]string, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Return copies to avoid race conditions if caller modifies them
	lines := make([]string, len(h.capturedLinesForSync))
	copy(lines, h.capturedLinesForSync)
	buffer := h.lineBufferForCapture.String()
	return lines, buffer
}

// ResetCapturedLinesAndSetBuffer clears captured lines and sets the current line buffer.
// Used after a /keystroke_sync command.
func (h *TermEventHandler) ResetCapturedLinesAndSetBuffer(newBufferContent string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.capturedLinesForSync = h.capturedLinesForSync[:0] // Clear slice
	h.lineBufferForCapture.Reset()
	h.lineBufferForCapture.WriteString(newBufferContent)
}
