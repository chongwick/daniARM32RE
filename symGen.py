'''
ARM 32-bit peripheral input fuzzer. Using concolic execution techniques to generate values
for unique path emulation.

Using Capstone disassembly framework
'''
import sys
import struct
from capstone import *
from collections import OrderedDict
import binascii

FILE_NAME = ''
IMAGEBASE = '0x80000'
IS_THUMB_MODE = 1
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

class EngineCore(object):
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

    def run(self):
        self.load_file()
        self.parse_isr()
        for i in range(len(self.file_data)):
            self.mem_instr.append(0)
        self.disassemble()
        #for i in range(len(self.mem_instr)):
        #    if self.mem_instr[i] != 0:
        #        print('%u\t%s'%(i, self.mem_instr[i]))
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

    def dasm_single(self, md, code, addr):
        for(address, size, mnemonic, op_str) in md.disasm_lite(code, 
                addr):
            self.curr_mnemonic = str(mnemonic)
            self.curr_op_str = str(op_str)
            instr = self.curr_mnemonic + '\t' + self.curr_op_str
            print('%s\t%s'%(hex(address), instr))
            if self.mem_instr[address-int(IMAGEBASE,16)] == 0:
                self.mem_instr[address-int(IMAGEBASE,16)] = instr
                return True
            else:
                return False

    def load_file(self):
        with open(self.filename, 'rb') as f:
            self.file_data = f.read()
        f.close()

    def parse_isr(self):
        self.hex_data = binascii.hexlify(self.file_data)
        # Stack top stored in first word, starting address in second
        self.stack_top = self.endian_switch(self.hex_data[0:8])
        self.starting_address = self.endian_switch(self.hex_data[8:16]) 
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

    # https://www.capstone-engine.org/lang_python.html
    def disassemble(self):
        start = (self.starting_address - int(IMAGEBASE, 16) - 1) * 2
        curr_instr = start
        curr_addr = self.starting_address - IS_THUMB_MODE
        code = self.hex_data[curr_instr:curr_instr+4].decode('hex')

        while(self.dasm_single(MD, code, curr_addr)):
            if IS_THUMB_MODE:
                curr_instr += 4
                curr_addr += 2 
            else:
                curr_instr += 8
                curr_addr += 4
            code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
            if self.curr_mnemonic in self.branch_instructions:
                if 'x' in self.curr_mnemonic:
                    self.toggle_thumb()
                curr_instr = (int(self.curr_op_str[1:], 16) - int(IMAGEBASE, 16)) * 2
                curr_addr = int(self.curr_op_str[1:], 16)
                code = self.hex_data[curr_instr:curr_instr+4].decode('hex')
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
    ec = EngineCore(FILE_NAME)
    ec.run()

if __name__ == '__main__':
    main()
