'''
ARM 32-bit peripheral input fuzzer. Using concolic execution techniques to generate values
for unique path emulation.

Using Capstone disassembly and Unicorn emulation framework
'''
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
from z3 import *
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

class DisassemblerCore(object):
    def __init__(self, filename):
        self.filename = filename
        self.file_data = b''
        self.hex_data = ''
        self.starting_address = ''
        self.stack_top = ''
        self.isr_num = 0
        self.isr_table_length = 0
        self.isr_pointers = []
        self.mem_instr = []
        self.branch_instructions = {'b', 'bl', 'blx', 'bx'}
        self.conditional_branches = {'blgt', 'blvc', 'blcc', 'blhs', 'blmi', 'blne', 'blal',
                'blle', 'blge', 'blvs',
                'blls', 'bllt', 'bllo', 'blcs', 'blhi', 'bleq', 'blpl', 'bgt', 'bvc', 'bcc',
                'bhs', 'bmi', 'bne', 'bal', 'ble', 'bge', 'bvs', 'bls', 'blt', 'blo', 'bcs',
                'bhi', 'beq', 'bpl', 'bxgt', 'bxvc', 'bxcc', 'bxhs', 'bxmi', 'bxne', 'bxal',
                'bxle', 'bxge', 'bxvs', 'bxls', 'bxlt', 'bxlo', 'bxcs', 'bxhi', 'bxeq', 'bxpl',
                'blxgt', 'blxvc', 'blxcc', 'blxhs', 'blxmi', 'blxne', 'blxal', 'blxle', 'blxge',
                'blxvs', 'blxls', 'blxlt', 'blxlo', 'blxcs', 'blxhi', 'blxeq', 'blxpl',
                'cbz', 'cbnz'}
        self.curr_mnemonic = ''
        self.curr_op_str = ''
        self.done = False
        self.size = 0
        self.subroutine_branch = []

    def run(self):
        self.load_file()
        for i in range(len(self.file_data)):
            self.mem_instr.append(0)
        self.disassemble()
        print('\n\n\nDisassembly\n\n\n')
        for i in range(len(self.mem_instr)):
            if self.mem_instr[i] != 0:
                print('%s\t%s'%(hex(i+int(IMAGEBASE,16)), self.mem_instr[i]))
        return True

    # Takes a hex representation and returns an int
    def endian_switch(self, val):
        tmp = "0x" + val[6] + val[7] + val[4] + val[5] + val[2] + val[3] + val[0] + val[1]
        return(int(tmp,16))

    def toggle_thumb(self):
        if IS_THUMB_MODE == 1:
            IS_THUMB_MODE = 0
            MD = Cs(CS_ARCH_ARM, CS_MODE_ARM)
        elif IS_THUMB_MODE == 0:
            IS_THUMB_MODE = 1
            MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

    def load_file(self):
        with open(self.filename, 'rb') as f:
            self.file_data = f.read()
        f.close()
        self.hex_data = binascii.hexlify(self.file_data)
        # Stack top stored in first word, starting address in second
        self.stack_top = self.endian_switch(self.hex_data[0:8])
        self.starting_address = self.endian_switch(self.hex_data[8:16])
        if self.starting_address % 2 != 0:
            IS_THUMB_MODE = 1
        else:
            IS_THUMB_MODE = 0
        # Detect endianness. (See daniEmu source code documentation if it's open source by now)
        index = 16
        while (True):
            address = self.endian_switch(self.hex_data[index:index+8])
            index += 8
            if address != 0:
                if ((address % 2 == 0) or
                        (address > self.starting_address + len(self.file_data)) or
                        (address < self.starting_address - len(self.file_data))):
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
           self.starting_address = int(self.hex_data[8:16], 16)
           self.stack_top = int(self.hex_data[0:8], 16)
           while (True):
               address = int(self.hex_data[index:index+8], 16)
               index += 8
               if address != 0:
                   if ((address % 2 == 0) or
                           (address > self.starting_address + len(self.file_data)) or
                           (address < self.starting_address - len(self.file_data))):
                       break;
               if (address != 0) and (address not in self.isr_pointers):
                   self.isr_pointers.append(address)
           self.isr_table_length += 1

    def dasm_single(self, md, code, addr):
        self.size = 0
        for(address, size, mnemonic, op_str) in md.disasm_lite(code,
                addr):
            self.size+=2
            self.curr_mnemonic = str(mnemonic)
            self.curr_op_str = str(op_str)
            instr = self.curr_mnemonic + '\t' + self.curr_op_str
            if self.mem_instr[address-int(IMAGEBASE,16)] == 0:
                self.mem_instr[address-int(IMAGEBASE,16)] = instr
                #debugging
                print('%s\t%s'%(hex(address), instr))
                return True
            else:
                return False

    def subroutine_branch_handler(self, curr_addr):
        if 'l' in self.curr_mnemonic:
            self.subroutine_branch.append(curr_addr+self.size)
            for i in self.subroutine_branch:
                print(hex(i))
            return False
        elif 'lr' in self.curr_op_str:
            curr_instr = (int(self.subroutine_branch[-1], 16) - int(IMAGEBASE, 16))*2
            curr_addr = int(self.subroutine_branch[-1],16)
            return True
            print(curr_instr)
        else:
            return False
        if 'pop' in self.curr_mnemonic:
            return True

    # https://www.capstone-engine.org/lang_python.html
    def disassemble(self):
        # Record conditional branch destinations
        con_br_dst = []
        start = (self.starting_address - int(IMAGEBASE, 16) - 1) * 2
        curr_instr = start
        curr_addr = self.starting_address - IS_THUMB_MODE
        code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
        prev_addr = 0
        reg_br_addr = 0
        while(True):
            if self.dasm_single(MD, code, curr_addr):
                prev_addr = curr_addr
                curr_instr += self.size*2
                curr_addr += self.size 
                code = self.hex_data[curr_instr:curr_instr+MAX_INSTR_SIZE].decode('hex')
                if self.curr_mnemonic == 'ldr' and 'pc' in self.curr_op_str:
                    arg = self.curr_op_str.split('#')[1]
                    arg = int(arg[:-1],16)
                    loc = int(math.floor((prev_addr + arg)/4)*4)
                    # 8 for doubleword offset
                    loc = int(loc - int(IMAGEBASE, 16)) * 2 + 8
                    data = self.hex_data[loc:loc+8]
                    reg_br_addr = self.endian_switch(data)-1
                if self.curr_mnemonic in self.branch_instructions:
                    if self.subroutine_branch_handler(curr_addr):
                        break
                    if self.curr_op_str in REGISTER_NAMES:
                        curr_instr = (reg_br_addr - int(IMAGEBASE, 16)) * 2
                        curr_addr = reg_br_addr
                        code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
                    else:
                        curr_instr = (int(self.curr_op_str[1:], 16) - int(IMAGEBASE, 16)) * 2
                        curr_addr = int(self.curr_op_str[1:], 16)
                        code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
                elif self.curr_mnemonic in self.conditional_branches:
                    if self.curr_mnemonic == 'cbz' or self.curr_mnemonic == 'cbnz':
                        con_br_dst.append(self.curr_op_str.split('#')[1])
                    elif self.curr_op_str in REGISTER_NAMES:
                        con_br_dst.append(hex(reg_br_addr))
                    elif self.curr_op_str[1:] not in con_br_dst:
                        con_br_dst.append(self.curr_op_str[1:])
            else:
                if len(con_br_dst) == 0:
                    break
                    self.done = True
                if not self.done:
                    print(con_br_dst)
                    curr_instr = (int(con_br_dst[-1], 16) - int(IMAGEBASE, 16)) * 2
                    curr_addr = int(con_br_dst[-1], 16)
                    code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
                    del(con_br_dst[-1])

# Main
def main():
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

if __name__ == '__main__':
    main()
