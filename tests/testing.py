from core.keyboard import USBKeyboard
import glob, os

class TestPassed:
    def __init__(self, filename):
        self.filename = filename
    def __str__(self):
        return f"Test Passed {self.filename}"

class TestFailed:
    def __init__(self, filename):
        self.filename = filename
    def __str__(self):
        return f"Test Failed {self.filename}"

if __name__ == "__main__":
    files = [file for file in glob.glob("assets/*") if os.path.isfile(file)]
    for filepath in files:
        try:
            keyboard = USBKeyboard(filepath)
            _ = keyboard.decode()
            print(TestPassed(filename=filepath))
        except:
            print(TestFailed(filename=filepath))


## TO RUN THE TEST CASES
## python3 -m tests.testing