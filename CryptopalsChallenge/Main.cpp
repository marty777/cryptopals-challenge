#include "Set1.h"
#include "Set2.h"
#include "Set3.h"


// the following should let me enable ansi escape codes in windows, but maybe only in Win10
// Taken from https://solarianprogrammer.com/2019/04/08/c-programming-ansi-escape-codes-windows-macos-linux-terminals/
#ifdef _WIN32
#include <windows.h>
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING  0x0004
#endif	

#include <stdio.h>

static HANDLE stdoutHandle;
static DWORD outModeInit;

void setupConsole() {
	DWORD outMode = 0;
	stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

	if (stdoutHandle == INVALID_HANDLE_VALUE) {
		exit(GetLastError());
	}
	
	if (!GetConsoleMode(stdoutHandle, &outMode)) {
		exit(GetLastError());
	}

	outModeInit = outMode;
    // Enable ANSI escape codes
	outMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

	if (!SetConsoleMode(stdoutHandle, outMode)) {
		exit(GetLastError());
	}
}

void restoreConsole() {
	// Reset colors
	printf("\x1b[0m");
	
	// Reset console mode
	if (!SetConsoleMode(stdoutHandle, outModeInit)) {
		exit(GetLastError());
	}
}
#else
void setupConsole() {}

void restoreConsole() {
	// Reset colors
	printf("\x1b[0m");
}
#endif

int main() {
	//setupConsole();
	//Set1();
	//Set2();
	Set3();
	//restoreConsole();
}