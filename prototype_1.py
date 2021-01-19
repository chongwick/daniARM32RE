''' 80856
ARM 32-bit full binary disassembler using Capstone disassembly framework.
- Daniel Chong
'''
'''
NOTE: CORTEX M processors use THUMB instructions exclusively https://stackoverflow.com/questions/28669905/what-is-the-difference-between-the-arm-thumb-and-thumb-2-instruction-encodings
https://www.keil.com/support/man/docs/armasm/armasm_dom1361289866466.htm
'''
import sys
import struct
from capstone import *
from collections import OrderedDict
import binascii
import math

FILE_NAME = ''
IMAGEBASE = '0x80000'
IS_THUMB_MODE = 1
MAX_INSTR_SIZE = 8
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
REGISTER_NAMES = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'
        , 'r10', 'sl', 'r11', 'r12', 'r13', 'r14', 'r15', 'psr', 'lr', 'pc', 'sp']
BRANCH_INSTRUCTIONS = {'b', 'bl', 'blx', 'bx'}
CONDITIONAL_BRANCHES =  {'blgt', 'blvc', 'blcc', 'blhs', 'blmi', 'blne', 'blal',
        'blle', 'blge', 'blvs',
        'blls', 'bllt', 'bllo', 'blcs', 'blhi', 'bleq', 'blpl', 'bgt', 'bvc', 'bcc',
        'bhs', 'bmi', 'bne', 'bal', 'ble', 'bge', 'bvs', 'bls', 'blt', 'blo', 'bcs',
        'bhi', 'beq', 'bpl', 'bxgt', 'bxvc', 'bxcc', 'bxhs', 'bxmi', 'bxne', 'bxal',
        'bxle', 'bxge', 'bxvs', 'bxls', 'bxlt', 'bxlo', 'bxcs', 'bxhi', 'bxeq', 'bxpl',
        'blxgt', 'blxvc', 'blxcc', 'blxhs', 'blxmi', 'blxne', 'blxal', 'blxle', 'blxge',
        'blxvs', 'blxls', 'blxlt', 'blxlo', 'blxcs', 'blxhi', 'blxeq', 'blxpl',
        'cbz', 'cbnz'}

#Record the location of branch instructions in the binary
BRANCHES = {}
MEM_INSTR = []
STARTING_ADDRESS = ''
HEX_DATA = ''

# Takes a hex representation and returns an int
def endian_switch(val):
    tmp = "0x" + val[6] + val[7] + val[4] + val[5] + val[2] + val[3] + val[0] + val[1]
    return(int(tmp,16))

class instr_data(object):
    def __init__(self, instr, op):
        self.instr = instr
        self.op = op

class DisassemblerCore(object):
    def __init__(self, filename):
        global MEM_INSTR
        global BRANCHES
        self.filename = filename
        self.file_data = b''
        self.starting_address = ''
        self.beginning_code = ''
        self.stack_top = ''
        self.isr_num = 0
        self.isr_table_length = 0
        self.isr_pointers = []
        self.curr_mnemonic = ''
        self.curr_op_str = ''
        self.done = False
        #Keep track of the size of the instruction (can be determined by Capstone)
        self.size = 0
        self.subroutine_branch = []

    def run(self):
        self.load_file()
        for i in range(len(self.file_data)):
            MEM_INSTR.append(0)
        self.disassemble()
        #print('\n\n\nDisassembly\n\n\n')
        disassembled_instrs = 0
        for i in range(len(MEM_INSTR)):
            if MEM_INSTR[i] != 0:
                disassembled_instrs += 1
                print('%s\t%s'%(hex(i+int(IMAGEBASE,16)), MEM_INSTR[i].instr+' '+MEM_INSTR[i].op))
                #if 'b\t#' + hex(i+int(IMAGEBASE,16)) == MEM_INSTR[i]:
                #    print'banana'
                #    break;
        #print BRANCHES
        print('NUMBER OF DISASSEMBLED INSTRUCTIONS:')
        print(disassembled_instrs)
        return True

    def load_file(self):
        global HEX_DATA, STARTING_ADDRESS
        with open(self.filename, 'rb') as f:
            self.file_data = f.read()
        f.close()
        HEX_DATA = binascii.hexlify(self.file_data)
        # Stack top stored in first word, starting address in second
        self.stack_top = endian_switch(HEX_DATA[0:8])
        self.starting_address = endian_switch(HEX_DATA[8:16])
        STARTING_ADDRESS = self.starting_address
        if self.starting_address % 2 != 0:
            IS_THUMB_MODE = 1
        else:
            IS_THUMB_MODE = 0
        # Detect endianness. (See daniEmu source code documentation if it's open source by now)
        index = 16
        while (True):
            address = endian_switch(HEX_DATA[index:index+8])
            index += 8
            if address != 0:
                if ((address % 2 == 0) or
                        (address > self.starting_address + len(self.file_data)) or
                        (address < self.starting_address - len(self.file_data))):
                    #Weird offset because of "index+=8" and self.beginning_code-thumb_mode
                    self.beginning_code = int(IMAGEBASE,16) + (index-8)/2 + 1
                    print(hex(self.beginning_code))
                    break;
            if(address != 0):
                self.isr_num += 1
            if (address != 0) and (address not in self.isr_pointers):
                self.isr_pointers.append(address)
            self.isr_table_length += 1
        if self.isr_num < 8 or self.starting_address > int("0x40000000", 16):
           print(">>>>BIG ENDIAN DETECTED<<<<")
           index = 16
           del(self.isr_pointers[:])
           self.starting_address = int(HEX_DATA[8:16], 16)
           self.stack_top = int(HEX_DATA[0:8], 16)
           while (True):
               address = int(HEX_DATA[index:index+8], 16)
               index += 8
               if address != 0:
                   if ((address % 2 == 0) or
                           (address > self.starting_address + len(self.file_data)) or
                           (address < self.starting_address - len(self.file_data))):
                       self.beginning_code = address
                       break;
               if (address != 0) and (address not in self.isr_pointers):
                   self.isr_pointers.append(address)
           self.isr_table_length += 1

    #Disassemble ONE instruction
    def dasm_single(self, md, code, addr):
        #Keep track of the number of instructions disassembled
        count = 0
        for(address, size, mnemonic, op_str) in md.disasm_lite(code,
                addr):
            count += 1
            self.curr_mnemonic = str(mnemonic)
            self.curr_op_str = str(op_str)
            instr = self.curr_mnemonic + '\t' + self.curr_op_str
            #MEM_INSTR[address-int(IMAGEBASE,16)] = instr
            MEM_INSTR[address-int(IMAGEBASE,16)] = instr_data(self.curr_mnemonic, self.curr_op_str)
            #if self.curr_mnemonic in self.branch_instructions or self.curr_mnemonic in self.conditional_branches:
            #   BRANCHES[address-int(IMAGEBASE,16)] = str(self.curr_mnemonic) + ', ' + str(self.curr_op_str)
            #debugging
#            print('%s\t%s\t%s\t\t%s'%(hex(address), instr, size, binascii.hexlify(code)))
        '''dasm_single is given 4 bytes. If Capstone is only able to disassemble 1 2-byte instruction,
           the second 2 bytes of the 4 belong to the next instruction.'''
        if count == 1 and size == 2:
            return False
        else:
            return True

    # https://www.capstone-engine.org/lang_python.html
    def disassemble(self):
        start = (self.beginning_code - int(IMAGEBASE, 16) - 1) * 2
        #start = (self.starting_address - int(IMAGEBASE, 16) - 1) * 2
        self.curr_instr = start
        self.curr_addr = self.beginning_code - IS_THUMB_MODE  #offset for thumb
        #self.curr_addr = self.starting_address - IS_THUMB_MODE
        # Section of code to be disassembled
        code = HEX_DATA[self.curr_instr:self.curr_instr+MAX_INSTR_SIZE].decode('hex')
        prev_addr = 0
        while(self.curr_instr+MAX_INSTR_SIZE < len(HEX_DATA)):
            if self.dasm_single(MD, code, self.curr_addr):
                self.curr_instr += MAX_INSTR_SIZE
                self.curr_addr += 4
            else:
                self.curr_instr += MAX_INSTR_SIZE/2
                self.curr_addr += 2
            code = HEX_DATA[self.curr_instr:self.curr_instr+MAX_INSTR_SIZE].decode('hex')


    def toggle_thumb(self):
        if IS_THUMB_MODE == 1:
            IS_THUMB_MODE = 0
            MD = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif IS_THUMB_MODE == 0:
            IS_THUMB_MODE = 1
            MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

class path_data:
    def __init__(self, path1, path2):
        self.path = path1
        self.branch_path = path2
        self.sources = []
        self.mode = ''
        self.arg = ''

class GeneratorCore(object):
    def __init__(self, disassembly, branches):
        self.mem_instr = disassembly
        self.branches = branches
        self.paths = {}

    def run(self):
        self.generate_paths()
        for i in self.paths:
            if len(self.paths[i].sources) == 0:
                self.paths[i] = 'Invalid'
            else:
                print("Address: %s  First Path: %s   Branch Path: %s   Instruction: %s"%(hex(i), hex(self.paths[i].path), hex(self.paths[i].branch_path), self.paths[i].arg))
        
           #     print("Address: %s  First Path: %s   Branch Path: %s   Instruction: %s"%(hex(i), hex(self.paths[i].path), hex(self.paths[i].branch_path)))
            
    def generate_paths(self):
        '''mem_instr and branches have the imagebase subtracted from them!!'''
        global STARTING_ADDRESS, MEM_INSTR, BRANCHES, BRANCH_INSTRUCTIONS, CONDITIONAL_BRANCHES, HEX_DATA

        register_branches = {}
        register_branches['r0'] = []
        register_branches['r1'] = []
        register_branches['r2'] = []
        register_branches['r3'] = []
        register_branches['r4'] = []
        register_branches['r5'] = []
        register_branches['r6'] = []
        register_branches['r7'] = []
        register_branches['r8'] = []
        register_branches['r9'] = []
        register_branches['r10'] = []
        register_branches['r11'] = []
        register_branches['r12'] = []
        register_branches['r13'] = []
        register_branches['r14'] = []
        register_branches['r15'] = []
        register_branches['lr'] = []
        
        i = STARTING_ADDRESS-int(IMAGEBASE,16)-IS_THUMB_MODE

        while i < range(len(MEM_INSTR)):
            if MEM_INSTR[i] != 0:

                instr = MEM_INSTR[i].instr
                op = MEM_INSTR[i].op

                #Calculate branch destinations when argument is a register
                if instr == 'ldr' and 'pc' in op:
                    addr = i + int(IMAGEBASE, 16)
                    reg = op.split(',')[0]
                    arg = op.split('#')[1]
                    arg = int(arg[:-1],16)
                    loc = int(math.floor((addr + arg)/4)*4)
                    # 8 for doubleword offset
                    loc = int(loc - int(IMAGEBASE, 16)) * 2 + 8
                    data = HEX_DATA[loc:loc+8]
                    reg_br_addr = endian_switch(data)-1
                    register_branches[reg].append(reg_br_addr)

                if instr in BRANCH_INSTRUCTIONS:
                    if 'bl' in instr:
                        register_branches['lr'].append(i+int(IMAGEBASE,16)+2)

                    if op in REGISTER_NAMES:
                        self.paths[i+int(IMAGEBASE,16)] = path_data(0, register_branches[op].pop())
                        self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                        if op == 'lr':
                            print instr + op
                            break;
                    else:
                        self.paths[i+int(IMAGEBASE,16)] = path_data(0, int(op.split('#')[1],16))
                        self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op

                elif instr in CONDITIONAL_BRANCHES:
                    if 'bl' in instr:
                        register_branches['lr'].append(i+int(IMAGEBASE,16)+2)
                    index = i + 1
                    while(MEM_INSTR[index] == 0):
                        index += 1
                    index += int(IMAGEBASE,16)
                    if op in REGISTER_NAMES:
                        self.paths[i+int(IMAGEBASE,16)] = path_data(index, register_branches[op].pop())
                        self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
                        if op == 'lr':
                            print instr + op
                            break;
                    else:
                        self.paths[i+int(IMAGEBASE,16)] = path_data(index, int(op.split('#')[1],16))
                        self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op

                else:
                    index = i + 1
                    while(MEM_INSTR[index] == 0):
                        index += 1
                    index += int(IMAGEBASE,16)
                    self.paths[i+int(IMAGEBASE,16)] = path_data(index, 0)
                    self.paths[i+int(IMAGEBASE,16)].arg = instr + ' ' + op
            i += 1
        if len(self.paths[STARTING_ADDRESS-int(IMAGEBASE,16)-IS_THUMB_MODE].sources) == 0:
            self.paths[STARTING_ADDRESS-int(IMAGEBASE,16)-IS_THUMB_MODE].sources.append(0)
        return 0

# Main
def main():
    tmp = False
    if len(sys.argv) > 1:
        FILE_NAME = str(sys.argv[1])
        #IMAGEBASE = str(sys.argv[2])
        with open('startup.txt', 'w') as f:
            f.write(FILE_NAME)
            #f.write(IMAGEBASE)
            f.close()
    else:
        with open('startup.txt', 'r') as f:
            FILE_NAME = f.readline()
            f.close()
        if len(FILE_NAME) == 0:
            print('No file found')
            return True
    dc = DisassemblerCore(FILE_NAME)
    dc.run()
    gc = GeneratorCore(MEM_INSTR, BRANCHES)
    gc.run()

if __name__ == '__main__':
    main()
