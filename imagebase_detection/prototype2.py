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
import numpy as np
import matplotlib.pyplot as plt

FILE_NAME = ''
IMAGEBASE = '0x80000'
IS_THUMB_MODE = 1
BRANCHED = []
TOP_ADDRESS = 0
MAX_INSTR_SIZE = 8
MD = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
REGISTER_NAMES = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9'
        , 'r10', 'sl', 'r11', 'r12', 'r13', 'r14', 'r15', 'psr', 'lr', 'pc', 'sp']
BRANCH_INSTRUCTIONS = {'b', 'bl', 'blx', 'bx', 'b.w', 'bl.w', 'blx.w', 'bx.w'}
CONDITIONAL_BRANCHES =  {'blgt', 'blvc', 'blcc', 'blhs', 'blmi', 'blne', 'blal',
        'blle', 'blge', 'blvs',
        'blls', 'bllt', 'bllo', 'blcs', 'blhi', 'bleq', 'blpl', 'bgt', 'bvc', 'bcc',
        'bhs', 'bmi', 'bne', 'bal', 'ble', 'bge', 'bvs', 'bls', 'blt', 'blo', 'bcs',
        'bhi', 'beq', 'bpl', 'bxgt', 'bxvc', 'bxcc', 'bxhs', 'bxmi', 'bxne', 'bxal',
        'bxle', 'bxge', 'bxvs', 'bxls', 'bxlt', 'bxlo', 'bxcs', 'bxhi', 'bxeq', 'bxpl',
        'blxgt', 'blxvc', 'blxcc', 'blxhs', 'blxmi', 'blxne', 'blxal', 'blxle', 'blxge',
        'blxvs', 'blxls', 'blxlt', 'blxlo', 'blxcs', 'blxhi', 'blxeq', 'blxpl',
        'cbz', 'cbnz', 'blgt.w', 'blvc.w', 'blcc.w', 'blhs.w', 'blmi.w', 'blne.w', 'blal.w',
        'blle.w', 'blge.w', 'blvs.w', 'blls.w', 'bllt.w', 'bllo.w', 'blcs.w', 'blhi.w', 'bleq.w',
        'blpl.w', 'bgt.w', 'bvc.w', 'bcc.w', 'bhs.w', 'bmi.w', 'bne.w', 'bal.w', 'ble.w', 'bge.w',
        'bvs.w', 'bls.w', 'blt.w', 'blo.w', 'bcs.w', 'bhi.w', 'beq.w', 'bpl.w', 'bxgt.w', 'bxvc.w',
        'bxcc.w', 'bxhs.w', 'bxmi.w', 'bxne.w', 'bxal.w', 'bxle.w', 'bxge.w', 'bxvs.w', 'bxls.w',
        'bxlt.w', 'bxlo.w', 'bxcs.w', 'bxhi.w', 'bxeq.w', 'bxpl.w', 'blxgt.w', 'blxvc.w', 'blxcc.w',
        'blxhs.w', 'blxmi.w', 'blxne.w', 'blxal.w', 'blxle.w', 'blxge.w', 'blxvs.w', 'blxls.w',
        'blxlt.w', 'blxlo.w', 'blxcs.w', 'blxhi.w', 'blxeq.w', 'blxpl.w', 'cbz.w', 'cbnz.w'}

#Record the location of branch instructions in the binary
BRANCHES = {}
MEM_INSTR = []
STARTING_ADDRESS = ''
HEX_DATA = ''
ISR_POINTERS = []

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
        ISR_POINTERS = []
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
                #print('%s\t%s'%(hex(i), MEM_INSTR[i].instr+' '+MEM_INSTR[i].op))
        #        #if 'b\t#' + hex(i+int(IMAGEBASE,16)) == MEM_INSTR[i]:
        #        #    print'banana'
        #        #    break;
        ##print BRANCHES
        #print('NUMBER OF DISASSEMBLED INSTRUCTIONS:')
        #print(disassembled_instrs)
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
                    self.beginning_code = (index-8)/2 + 1
                    #print(hex(self.beginning_code))
                    break;
            if(address != 0):
                self.isr_num += 1
            if (address != 0) and (address not in ISR_POINTERS):
                ISR_POINTERS.append(address)
            self.isr_table_length += 1
        if self.isr_num < 8 or self.starting_address > int("0x40000000", 16):
           print(">>>>BIG ENDIAN DETECTED<<<<")
           index = 16
           del(ISR_POINTERS[:])
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
               if (address != 0) and (address not in ISR_POINTERS):
                   ISR_POINTERS.append(address)
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
            MEM_INSTR[address] = instr_data(self.curr_mnemonic, self.curr_op_str)
            if self.curr_mnemonic in BRANCH_INSTRUCTIONS or self.curr_mnemonic in CONDITIONAL_BRANCHES:
                if 'r' not in self.curr_op_str and 's' not in self.curr_op_str:
                    BRANCHED.append(int(self.curr_op_str.split('#')[1],16))
                    #print('branchk:', self.curr_mnemonic, self.curr_op_str)
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
        start = (self.beginning_code - 1) * 2
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

def cleanse_data(data_set):
    mean = 0
    for i in data_set:
        mean += i
    mean = mean/len(data_set)
    print 'mean',hex(mean)
    std = np.std(data_set)
    upper_limit = mean + 3 * std
    lower_limit = mean - 3 * std
    print 'upper',hex(int(upper_limit)),'lower',hex(int(lower_limit))
    removed = 0
    low = 0
    high = 0
    while(min(BRANCHED) < lower_limit):
        data_set.remove(min(data_set))
        low += 1 
    while(max(data_set) > upper_limit):
        print(hex(max(data_set)))
        data_set.remove(max(data_set))
        high += 1
    print 'done'
    if low > high:
        return 'low'
    elif high > low:
        return 'high'
    else:
        return 'even'

def hist_plot(data_set):
    bin_number = math.ceil(math.sqrt(len(data_set)))
    print bin_number
    bin_width = (max(data_set)-min(data_set))/bin_number
    plt.hist(data_set, bins=bin_number);plt.show()

def find_imagebase(data_set, confirmed_addrs):
    test_imagebase = 0x80000
    tmp = [i + test_imagebase for i in data_set]
    result = ''
    for i in tmp:
        print hex(i)

    result = cleanse_data(tmp+confirmed_addrs)
    print result
    #while result != 'even':
    #    cleanse_data(data_set+confirmed_addrs)
    #    for i in tmp:
    #        i += 1

#0x40000000 is the max number where code can be stored
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
    print('\n\n')


    print 'length', len(BRANCHED)
    #hist_plot(BRANCHED)
    cleanse_data(BRANCHED)
    #hist_plot(BRANCHED)
    find_imagebase(BRANCHED, ISR_POINTERS)



    #mean = 0
    #for i in BRANCHED:
    #    mean += i
    #mean = mean/len(BRANCHED)
    #print mean

    #isr_std = np.std(ISR_POINTERS)
    #isr_mean = 0 
    #for i in ISR_POINTERS:
    #    isr_mean += i
    #isr_mean = isr_mean/len(ISR_POINTERS)
    #lower_limit = isr_mean - 2 * isr_std
    #upper_limit = isr_mean + 2 * isr_std
    #tmp = 0
    #minimum = min(BRANCHED)
    #maximum = max(BRANCHED)
    #while minimum < lower_limit:
    #    minimum += 1024
    #    tmp += 1024
    #print hex(tmp)

    #print 'lower', lower_limit, minimum
    #print 'upper',upper_limit, maximum+tmp
    #while maximum+tmp > upper_limit:
    #    tmp -= 1024
    #print hex(tmp)



    #BRANCHED.sort()
    #for i in BRANCHED:
    #    print hex(i)
    #combined = BRANCHED + ISR_POINTERS
    #mean = 0
    #for i in combined:
    #    mean += i
    #mean = mean/len(combined)
    #std = np.std(combined)
    #upper_limit = mean + 3 * std
    #lower_limit = mean - 3 * std
    #print('upper',upper_limit,'lower',lower_limit)
    #while(min(combined) < lower_limit):
    #    combined.remove(min(combined))
    #print hex(lower_limit)
    #print hex(min(combined))
    #page_size = 1024
    #addr = min(combined)
    #imagebase = addr & ~(page_size-1)
    #print('\n')
    #print hex(imagebase)


if __name__ == '__main__':
    main()
