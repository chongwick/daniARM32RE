'''
ARM 32-bit peripheral input fuzzer. Using concolic execution techniques to generate values
for unique path emulation.

Using Capstone disassembly and Unicorn emulation framework
'''
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *
import sys
import struct
from capstone import *
from collections import OrderedDict
import binascii

FILE_NAME = ''
IMAGEBASE = '0x80000'

class DisassemblerCore(object):
    def __init__(self):
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

    def run(self):
        self.load_input_file()
        self.init_emul()

    def endian_switch(self, val):
        tmp = "0x" + val[6] + val[7] + val[4] + val[5] + val[2] + val[3] + val[0] + val[1]
        return(int(tmp,16))

    def load_input_file(self):
        with open(FILE_NAME, 'rb') as f:
            self.file_data = f.read()
        f.close()
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

    def all_instr_hook_code(self, uc, ip_address, size, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(ip_address, size))
    def hook_mem_access(self, uc, access, ip_address, size, value, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(ip_address, size))
    def hook_mem_invalid(self, uc, access, ip_address, size, value, user_data):
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(ip_address, size))


    def init_emul(self):
        try:
            self.uc = Uc(IN_UC_ARCH, IN_UC_ARCH_MODE)
            tmp = len(self.file_data) // (1024 * 1024)
            self.mem_size = (1024 * 1024) + (tmp * (1024 * 1024)) 
            self.uc.mem_map(IMAGEBASE, self.mem_map)
            self.uc.mem_write(IMAGEBASE, self.file_data) 
            self.uc.reg_write(UC_ARM_REG_R0, 0)
            self.uc.reg_write(UC_ARM_REG_R1, 0)
            self.uc.reg_write(UC_ARM_REG_R2, 0)
            self.uc.reg_write(UC_ARM_REG_R3, 0)
            self.uc.reg_write(UC_ARM_REG_R4, 0)
            self.uc.reg_write(UC_ARM_REG_R5, 0)
            self.uc.reg_write(UC_ARM_REG_R6, 0)
            self.uc.reg_write(UC_ARM_REG_R7, 0)
            self.uc.reg_write(UC_ARM_REG_R8, 0)
            self.uc.reg_write(UC_ARM_REG_R9, 0)
            self.uc.reg_write(UC_ARM_REG_R10, 0)
            self.uc.reg_write(UC_ARM_REG_R11, 0)
            self.uc.reg_write(UC_ARM_REG_R12, 0)
            self.uc.reg_write(UC_ARM_REG_SP, self.stack_top)
            self.uc.hook_add(UC_HOOK_CODE, self.all_instr_hook_code)
            self.uc.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE, self.hook_mem_access)
            self.uc.hook_add(UC_HOOK_MEM_INVALID, self.hook_mem_invalid)
            self.uc.emu_start(self.starting_address, IMAGEBASE + self.mem_size-1)
        except Error as e:
            print('ERROR: %s'%e)

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
    dc = DisassemblerCore()
    dc.run()

if __name__ == '__main__':
    main()
