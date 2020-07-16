import sys
import struct
from capstone import *
from collections import OrderedDict
import binascii
from unicorn import *
from unicorn.arm_const import *
from unicorn.unicorn_const import *

IMAGEBASE = 0x80000
# Arm instructions are 4 bytes and thumb can be 2 or 4
MAX_INSTR_SIZE = 4
I = 0

class DisassemblerCore(object):
    def __init__(self):
        self.md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
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
        self.curr_instr = ''
        self.curr_op_str = ''
        self.cond_br_dst = []

    def run(self):
        global IMAGEBASE
        self.load_input_file()
        for i in range(len(self.file_data)):
            self.mem_instr.append(0)
        self.emul_run()
        g = 0
        for i in range(len(self.mem_instr)):
            if self.mem_instr[i] != 0:
                g += 1
                print('%s\t%s'%(hex(i+IMAGEBASE), self.mem_instr[i]))
        print(g)
    def endian_switch(self, val):
        tmp = "0x" + val[6] + val[7] + val[4] + val[5] + val[2] + val[3] + val[0] + val[1]
        return(int(tmp,16))

    def load_input_file(self):
        if len(sys.argv) > 1:
            file_name = str(sys.argv[1])
            #IMAGEBASE = str(sys.argv[2])
            with open('startup.txt', 'w') as f:
                f.write(file_name)
                #f.write(IMAGEBASE)
                f.close()
        else:
            with open('startup.txt', 'r') as f:
                file_name = f.readline()
                f.close()
            if len(file_name) == 0:
                print('No file found')
        with open(file_name, 'rb') as f:
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

    def set_mode(self, mode):
        if mode == UC_MODE_THUMB:
            self.md.mode = CS_MODE_THUMB
        else:
            self.md.mode = CS_MODE_ARM

    def dasm_single(self, code, addr):
        for(address, size, mnemonic, op_str) in self.md.disasm_lite(code, addr):
            self.curr_instr = str(mnemonic)
            self.curr_op_str = str(op_str)
            instr = self.curr_instr + '\t' + self.curr_op_str
            print('dasmrout %s\t%s'%(hex(addr), instr))
            if self.mem_instr[addr-IMAGEBASE] == 0:
                self.mem_instr[addr-IMAGEBASE] = instr
                if self.curr_instr in self.conditional_branches:
                    if self.uc.query(UC_QUERY_MODE) == UC_MODE_THUMB: 
                        self.cond_br_dst.append(int(self.curr_op_str[1:],16)+1)
                        #self.uc.reg_write(UC_ARM_REG_R15, int(self.curr_op_str[1:], 16)+1)
                    else:
                        self.cond_br_dst.append(int(self.curr_op_str[1:],16))
                        #self.uc.reg_write(UC_ARM_REG_R15, int(self.curr_op_str[1:], 16))
                return True
            else:
                return False

    def disassemble(self, addr, size):
        #start = (self.starting_address-IMAGEBASE-1)*2
        #address = self.starting_address-1
        #code = self.uc.mem_read(address, MAX_INSTR_SIZE)
        #code = '43f8042b'
        #code = code.decode('hex')
        #print(binascii.hexlify(code))
        code = self.uc.mem_read(addr, size)
        if not (self.dasm_single(code, addr)):
            try:
                self.uc.reg_write(UC_ARM_REG_R15, self.cond_br_dst[-1])
                del(self.cond_br_dst[-1])
            except Exception as e:
                if self.uc.query(UC_QUERY_MODE) == UC_MODE_THUMB:
                    nxt_instr = addr+size+1
                    self.uc.reg_write(UC_ARM_REG_R15, nxt_instr)
                else:
                    nxt_instr = addr+size+1
                    self.uc.reg_write(UC_ARM_REG_R15, nxt_instr)
        if self.curr_instr == 'b' and int(self.curr_op_str[1:],16) == addr:
            self.uc.emu_stop()

    #
    # Emulation code
    #
    def map_mem(self, addr, size = 0):
        page_size = self.uc.query(UC_QUERY_PAGE_SIZE)
        page_start = addr & ~(page_size-1)
        if size == 0:
            self.uc.mem_map(page_start, page_size)
            return(page_start)
        else:
            self.uc.mem_map(page_start, size)
            return(page_start)

    def all_instr_hook_code(self, uc, ip_address, size, user_data):
        global I
        #I += 1
        self.set_mode(self.uc.query(UC_QUERY_MODE))
        self.disassemble(ip_address, size)
        print("all_hook")
        #print(">>> Tracing basic block at 0x%x, instruction size = 0x%x" %(ip_address, size))
        #if I == 30:
        #    self.uc.emu_stop()

    def hook_mem_access(self, uc, access, ip_address, size, value, user_data):
        print("mem_acc")
        #print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(ip_address, size))

    def hook_mem_invalid(self, uc, access, ip_address, size, value, user_data):
        self.map_mem(ip_address)
        print("mem_invalid")
        return True

    def emul_run(self):
        try:
            self.uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
            self.mem_size = 0
            self.stack_size = (1024*1024)*2
            tmp = len(self.file_data) // (1024 * 1024)
            self.mem_size = (1024 * 1024) + (tmp * (1024 * 1024))
            self.map_mem(self.stack_top-self.stack_size/2, self.stack_size)
            self.uc.mem_map(IMAGEBASE, self.mem_size)
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
        except UcError as e:
            print('ERROR: %s'%e)
