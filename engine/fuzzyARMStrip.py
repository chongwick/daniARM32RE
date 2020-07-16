'''
ARM 32-bit peripheral input fuzzer. Using concolic execution techniques to generate values
for unique path emulation.

Using Capstone disassembly and Unicorn emulation framework
'''
from dasmCore import DisassemblerCore

# Main
def main():
    dc = DisassemblerCore()
    dc.run()

if __name__ == '__main__':
    main()
