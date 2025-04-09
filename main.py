from core.keyboard import *
import sys
import os
import shutil
import textwrap

# Check if terminal supports ANSI colors
USE_COLOR = sys.stdout.isatty() and os.name != 'nt'

GREEN = "\033[92m" if USE_COLOR else ""
RESET = "\033[0m" if USE_COLOR else ""

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: python main.py <file_path>\n")
        sys.exit(1)

    file_path = sys.argv[1]

    if os.path.exists(file_path):
        usb_keyboard = USBKeyboard(file_path)
        out = usb_keyboard.decode()
        terminal_width = shutil.get_terminal_size().columns
        max_width = min(terminal_width, 120)

        for ip, data in out.items():
            file_name =  ip + " => Host"
            decoded_text = ''.join(data)

            print(GREEN + "╔" + "═" * (max_width - 2) + "╗")
            print(f"║ {file_name[:max_width - 4]:<{max_width - 4}} ║")
            print("╟" + "─" * (max_width - 2) + "╢")

            for line in decoded_text.split("\n"):
                wrapped = textwrap.wrap(line, width=max_width - 4) or [""]
                for wline in wrapped:
                    sys.stdout.write("║ ")
                    for char in wline:
                        sys.stdout.write(char)
                        sys.stdout.flush()
                    sys.stdout.write(" " * (max_width - 4 - len(wline)))
                    sys.stdout.write(" ║\n")
            print("╚" + "═" * (max_width - 2) + "╝" + RESET)

    else:
        sys.stderr.write(f"File does not exist at path: {file_path}\n")
        sys.stderr.flush()
