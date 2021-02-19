#include <termios.h>
#include <unistd.h>

#include "terminal.hpp"

/**
 * A RAII stype class that turns off echo on console.
 * We use it for reading user secret from console.
 */
stdin_echo_off::stdin_echo_off()
{
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	tty.c_lflag &= ~ECHO;
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

stdin_echo_off::~stdin_echo_off()
{
	struct termios tty;
	tcgetattr(STDIN_FILENO, &tty);
	tty.c_lflag |= ECHO;
	(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
