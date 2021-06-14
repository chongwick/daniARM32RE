import r2pipe
import sys
from collections import OrderedDict
FUNCTION_ADDR = OrderedDict()
######################################################################################
######################################################################################
# AnalyzeElf
######################################################################################
######################################################################################
#Analyzes the .elf file to figure out what file is being run. Developed by Elijah who commented this pretty well.
#If you do have some questions about it I would recommend asking him.
def processFunction(r2, address, function_json):
    r2.cmd("s {}".format(address))
    r2.cmd("af")
    hex_instructions = []
    disassembled_instructions = []

    disassembly = r2.cmd("pdf")
    # Some functions can't be disassembled with the pdf command. Use pdr instead.
    if (disassembly == ""):
        disassembly = r2.cmd("pdr")

    disassembly_split = disassembly.split('\n')
    for instruction_line in disassembly_split:
        instruction = instruction_line.split(' ')

        try:
        # The output of pdf begins with several lines of comments. This conversion makes sure
        # we only capture the lines that begin with the hex representation of an instruction.
            int(instruction[0], base=16)
            hex_instructions.append(instruction[0])

            # The disassembled instruction is separated from the hex of the instruction by
            # a variable number of spaces. Find the next non-space character.
            disassembly_start = instruction.index(next(sub for sub in instruction[1:] if sub))

            # The disassembled instruction is often followed by several empty spaces and
            # comments. Find the empty space directly after the disassembled instruction.
            last_disassembly = next(
                (sub for sub in instruction[disassembly_start:] if not sub), 'not found'
            )

            disassembly_end = len(instruction)

            # If an empty space exists after the disassembled instruction, calculate its index.
            # Since a substring starting at the beginning of the instruction was used to find
            # it, its index in this substring must be found first, then the index of the
            # beginning of the instruction must be added to get the index in the full string.
            if not last_disassembly:
                disassembly_end = disassembly_start + instruction[disassembly_start:].index(last_disassembly)

            # Record the disassembled instruction
            disassembled_instructions.append(
                instruction[disassembly_start:disassembly_end]
            )

        except ValueError:
            continue
    function_json['hex'] = hex_instructions
    function_json['disassembly'] = disassembled_instructions

def openElf(filename):
    r2 = r2pipe.open(filename)
    # Several features in radare2 that make the disassembly easier for humans to read
    # also makes it more difficult to parse. Disable these options.
    r2.cmd('e asm.comments = false')
    r2.cmd('e asm.lines = false')
    r2.cmd('e asm.offset = false')
    r2.cmd('e asm.marks = false')

    # Radare2 has some trouble realizing that the first function it analyzes uses the Thumb
    # instruction set. This forces it to use Thumb.
    r2.cmd('ahb 16')

    # Gather the flags from the .elf file
    flag_dump = r2.cmd('f')

    flags = flag_dump.split('\n')

    # Using the split() function means that there will be one empty entry at the end of
    # the array. This removes that entry.
    flags.pop(len(flags)-1)
    flags.sort()
    functions = []
    # Every flag name that begins with ".sym" is the name of a function.
    # components[0]: function address
    # components[1]: some number (significance is unknown)
    # components[2]: flag name
    for flag in flags:
        flag_components = flag.split(' ')
        if 'sym.' in flag_components[2]:
            function_json = OrderedDict()
            FUNCTION_ADDR[str(flag_components[0])[5:].lstrip('0')] = flag_components[2][4:]
            processFunction(r2, flag_components[0], function_json)
    print(filename + " analysis complete... Don't worry, probably still gonna work")


def main():
    if (len(sys.argv) is not 2):
        ANALYZE_ELF = False
    else:
        openElf(sys.argv[1])
    g = []
    for i in FUNCTION_ADDR:
        try:
            t = '0x' + i
            t = int(t,16)
            print(t)
            g.append(t)
        except:
            t = 0
    f = open('banana.txt', 'r')
    tmp = f.read()
    tmp = tmp.split()
    print tmp
    f.close()
    for i in tmp:
        if i in g:
            print 'ih'

if __name__ == '__main__':
    main()
