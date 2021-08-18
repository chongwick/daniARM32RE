# Written by Nathaniel Boland
# for parsing ARM32 assembly.


import string
from collections import deque, defaultdict
from enum import Enum        
import copy

class MnemonicType(Enum):
    UNKNOWN = 0
    ARITHMETIC = 1
    COMPARISON = 2
    BRANCH = 3
    MODIFY = 4
    LOAD_STORE = 5
    STACK_CONTROL = 6

class Mnemonic(object):
    MODIFY = {"adc", "add", "and", "asr", "bfc", "bfi", "bic", "clz", "crc32b", "crc32h", 
              "crc32w", "crc32c", "eor", "lsl", "lsr", "mla", "mls", "mov", "movt", "movw", "mrs", 
              "mul", "mvn", "orn", "orr", "pkhbt", "pkhtb", "qadd", "qadd8", "qadd16", "qasx", 
              "qdadd", "qdsub", "qsax", "qsub", "qsub8", "qsub16", "rbit", "rev", "rev16", 
              "revsh", "ror", "rrx", "rsb", "rsc", "sadd8", "sadd16", "sasx", "sbc", "sbfx", 
              "sdiv", "sel", "shadd8", "shadd16", "shasx", "shsax", "shsub8", "shsub16", "smlaxy", 
              "smlad", "smlawy", "smlsd", "smmla", "smmls", "smmul", "smuad", "smulxy", "smulwy", 
              "smusd", "ssat", "ssat16", "ssax", "ssub8", "ssub16", "sub", "sxtab", "sxtab16", 
              "sxtah", "sxtb", "sxtb16", "sxth", "uadd8", "uadd16", "uasx", "ubfx", "udiv", 
              "uhadd8", "uhadd16", "uhasx", "uhasx", "uhsax", "uhsub8", "uhsub16", "uqadd8", 
              "uqadd16", "uqasx", "uqsax", "uqsub8", "uqsub16", "usad8", "usada8", "usat", 
              "usat16", "usax", "usub8", "usub16", "uxtab", "uxtab16", "uxtah", "uxtb", "uxtb16", 
              "uxth", "mov", "pop", "ldr", "ldrh", "ldrb", "ldrsb", "ldrh", "ldrsh", "ldrex"}
    LOAD = {"ldr", "ldrh", "ldrb", "ldrsb", "ldrh", "ldrsh", "ldrex", "ldm"}
    STORE = {"str", "strb", "strh", "stm"}
    LOAD_STORE = LOAD | STORE
    ARITHMETIC = {"adc", "add", "mul", "rsb", "rsc", "sbc", "sdiv", "udiv", "sub"}
    ADDITION_SUBTRACTION = {"adc", "add", "rsb", "rsc", "sbc", "sub"}
    ARITHMETIC_CARRY = {"adc", "rsc", "sbc"}
    ADDITION_CARRY = {"adc"}
    SUBTRACTION_CARRY = {"rsc", "sbc"}
    BRANCH  = {"b", "bl", "blx", "bx"}
    COMPARISON = {"cmp", "cmn"}
    MOVE = {"mov", "movt", "movw"}
    CONTROL_FLOW = {"it", "ite", "itee", "iteee", "itt", "itte", "ittee"}
    STACK_CONTROL = {"push", "pop"}
    POST_MNEMONICS = {"lsl", "lsr"}
    
    NO_SUFFIX = {"ldr", "ldrh", "ldrb", "ldrsb", "ldrh", "ldrsh", "ldrex", "ldm", "str", "strb", "strh", "stm", 
                 "b", "bl", "blx", "bx", "cmp", "cmn", "crc32b", "crc32c",  "rev", "rev16", "revsh"}
                 
    MNEMONICS = MODIFY | LOAD_STORE | BRANCH | COMPARISON | CONTROL_FLOW | STACK_CONTROL

    CONDITIONAL_CODES = {'gt', 'vc', 'cc', 'hs', 'mi', 'ne', 'al', 'le', 'ge', 'vs', 'ls', 'lt', 'lo', 'cs', 'hi', 'eq', 'pl'}
    SIGNED_CONDITIONAL_CODES = {'gt', 'lt', 'ge', 'le', 'mi', 'pl', 'vs', 'vc'}
    UNSIGNED_CONDITIONAL_CODES = {'cs', 'hs', 'cc', 'lo', 'hi', 'ls'}
        
    @classmethod
    def parse_mnemonic(cls, mnemonic_str):
        mnemonic = ""
        suffix = ""
        conditional_code = ""
        
        if mnemonic_str[-2:] == ".w":
            mnemonic_str = mnemonic_str[:-2]
                
        if mnemonic_str in Mnemonic.MNEMONICS:
            mnemonic = mnemonic_str
        elif mnemonic_str[:-1] in Mnemonic.MNEMONICS and not mnemonic_str[:-1] in Mnemonic.NO_SUFFIX and mnemonic_str[-1] == 's':
            mnemonic = mnemonic_str[:-1]
            suffix = mnemonic_str[-1]
        elif mnemonic_str[:-2] in Mnemonic.MNEMONICS:
            mnemonic = mnemonic_str[:-2]
            conditional_code = mnemonic_str[-2:]
        elif mnemonic_str[:-3] in Mnemonic.MNEMONICS and not mnemonic_str[:-3] in Mnemonic.NO_SUFFIX and mnemonic_str[-3] == 's':
            mnemonic = mnemonic_str[:-3]
            suffix = mnemonic_str[-3]
            conditional_code = mnemonic_str[-2:]
        else:
            mnemonic = mnemonic_str
            
        return mnemonic, suffix, conditional_code
        
    @classmethod
    def get_conditional_code(cls, mnemonic_str):
        conditional_code = ""
        
        if mnemonic_str[-2:] == ".w":
            mnemonic_str = mnemonic_str[:-2]
        if mnemonic_str[-2:] in Mnemonic.CONDITIONAL_CODES and (mnemonic_str[:-2] in Mnemonic.MNEMONICS or (mnemonic_str[:-3] in Mnemonic.MNEMONICS and mnemonic_str[-3] == 's')):
            conditional_code = mnemonic_str[-2:]
        
        return conditional_code
        
    @classmethod
    def retreve_arethmetic_mnemonic(cls, mnemonic_str):
        mnemonic = ""
        suffix = ""
        conditional_code = ""
        
        if mnemonic_str[-2:] == ".w":
            mnemonic_str = mnemonic_str[:-2]
        if mnemonic_str in Mnemonic.ARITHMETIC:
            mnemonic = mnemonic_str
        elif mnemonic_str[:-1] in Mnemonic.ARITHMETIC and mnemonic_str[-1] == 's':
            mnemonic = mnemonic_str[:-1]
            suffix = mnemonic_str[-1]
        elif mnemonic_str[:-2] in Mnemonic.ARITHMETIC:
            mnemonic = mnemonic_str[:-2]
            conditional_code = mnemonic_str[-2:]
        elif mnemonic_str[:-3] in Mnemonic.ARITHMETIC and mnemonic_str[-3] == 's':
            mnemonic = mnemonic_str[:-3]
            suffix = mnemonic_str[-3]
            conditional_code = mnemonic_str[-2:]
            
        return mnemonic, suffix, conditional_code
    
    @classmethod
    def is_arithmetic_mnemonic(cls, mnemonic_str):
        if mnemonic_str[-2:] == ".w":
            mnemonic_str = mnemonic_str[:-2]
        return mnemonic_str in Mnemonic.ARITHMETIC or mnemonic_str[:-1] in Mnemonic.ARITHMETIC or mnemonic_str[:-2] in Mnemonic.ARITHMETIC or mnemonic_str[:-3] in Mnemonic.ARITHMETIC
        
    @classmethod
    def is_carry_mnemonic(cls, mnemonic_str):
        return mnemonic_str[:3] in Mnemonic.ARITHMETIC_CARRY

    @classmethod
    def is_addition_carry_mnemonic(cls, mnemonic_str):
        return mnemonic_str[:3] in Mnemonic.ADDITION_CARRY

    @classmethod
    def is_subtraction_carry_mnemonic(cls, mnemonic_str):
        return mnemonic_str[:3] in Mnemonic.SUBTRACTION_CARRY
        
    def __init__(self, mnemonic_str=None):
        new_mnemonic = ""
        new_suffix = ""
        new_condition = ""
        new_mnemonic_type = None
        
        if mnemonic_str:
            new_mnemonic, new_suffix, new_condition = Mnemonic.parse_mnemonic(mnemonic_str)
            
            if new_mnemonic in Mnemonic.ARITHMETIC:
                new_mnemonic_type = MnemonicType.ARITHMETIC
            elif new_mnemonic in Mnemonic.COMPARISON:
                new_mnemonic_type = MnemonicType.COMPARISON
            elif new_mnemonic in Mnemonic.BRANCH:
                new_mnemonic_type = MnemonicType.BRANCH
            elif new_mnemonic in Mnemonic.MODIFY:
                new_mnemonic_type = MnemonicType.MODIFY
            elif new_mnemonic in Mnemonic.LOAD_STORE:
                new_mnemonic_type = MnemonicType.LOAD_STORE
            elif new_mnemonic in Mnemonic.STACK_CONTROL:
                new_mnemonic_type = MnemonicType.STACK_CONTROL
            else:
                new_mnemonic_type = MnemonicType.UNKNOWN
                
    
        self.name = new_mnemonic
        self.suffix = new_suffix
        self.condition = new_condition
        self.mnemonic_type = new_mnemonic_type
        
    def __str__(self):
        output = ""
        
        if self.name:
            output = self.name + self.suffix + self.condition
            
        return output
        
    def is_comparision(self):
        return (self.suffix or self.mnemonic_type == MnemonicType.COMPARISON)

    def set(self, mnemonic_str):
        new_mnemonic = ""
        new_suffix = ""
        new_condition = ""
        new_mnemonic_type = None
        
        if mnemonic_str:
            new_mnemonic, new_suffix, new_condition = Mnemonic.parse_mnemonic(mnemonic_str)
            
            if new_mnemonic in Mnemonic.ARITHMETIC:
                new_mnemonic_type = MnemonicType.ARITHMETIC
            elif new_mnemonic in Mnemonic.COMPARISON:
                new_mnemonic_type = MnemonicType.COMPARISON
            elif new_mnemonic in Mnemonic.BRANCH:
                new_mnemonic_type = MnemonicType.BRANCH
            elif new_mnemonic in Mnemonic.MODIFY:
                new_mnemonic_type = MnemonicType.MODIFY
            else:
                new_mnemonic_type = MnemonicType.UNKNOWN
                
    
        self.name = new_mnemonic
        self.suffix = new_suffix
        self.condition = new_condition
        self.mnemonic_type = new_mnemonic_type


class Operands(object):
    REGISTERS = {"r0":0, "r1":1, "r2":2, "r3":3, "r4":4, 
                 "r5":5, "r6":6, "r7":7, "r8":8, "r9":9, 
                 "r10":10, "r11":11, "r12":12, "r13":13, "r14":14, "r15":15,
                 "ip":12, "sp":13, "lr":14, "pc":15, "cpsr":16}
    
    INV_REGISTERS = {0:"r0", 1:"r1", 2:"r2", 3:"r3", 4:"r4", 
                     5:"r5", 6:"r6", 7:"r7", 8:"r8", 9:"r9", 
                     10:"r10", 11:"r11", 12:"ip", 13:"sp", 14:"lr", 15:"pc", 16:"cpsr"}

    @classmethod
    def string_to_operands(cls, operand_str):
        if operand_str[0] == '{':
            operand_str = operand_str.replace('{', '')
            operand_str = operand_str.replace('}', '')

        operand_list = operand_str.split(', [')
        
        secondary_operation = None
        operands = None
        
        # for bracket operations see https://azeria-labs.com/memory-instructions-load-and-store-part-4/
        if len(operand_list) == 2:
            bracket_and_after = operand_list[1].split(']')
            bracket_clause, secondary_bracket_instruction = cls.string_to_operands(bracket_and_after[0])
            
            if secondary_bracket_instruction:
                bracket_clause.append(secondary_bracket_instruction)
            
            operands = operand_list[0].split(', ')
            
            operands.append(bracket_clause)
            
            if bracket_and_after[1]:
                after_brackets = bracket_and_after[1].split(', ')
                
                if not after_brackets[0]:
                    after_brackets = after_brackets[1:]
                
                operands += after_brackets
            
        else:
            operands = operand_list[0].split(", ")
            secondary = operands[-1].split(' ')
            if secondary[0] in Mnemonic.POST_MNEMONICS:
                secondary_operation = secondary
                operands = operands[:-1]

            
        return operands, secondary_operation

        

    def __init__(self, operand_str=None):
        self._list = []
        self.secondary_operation = None
        
        if operand_str:
            self._list, self.secondary_operation = Operands.string_to_operands(operand_str)
            
    def __getitem__(self, key):
        return self._list[key]
        
    def __setitem__(self, key, value):
        self._list[key] = value
        

    def __len__(self):
        return len(self._list)
        
    def __str__(self):
        result = ""
        
        if self._list:
            for element in self._list:
                if result:
                    result += ", "
                    
                if element is string:
                    result += element
                    
                else:
                    result += str(element)
        
        if self.secondary_operation:
            result += str(self.secondary_operation)
        
        return result
        
    def set(self, operands):
        self._list = copy.deepcopy(operands._list)
        self.secondary_operation = operands._secondary_operation
            
    def str_set(self, operand_str):
        self._list, self.secondary_operation = Operand.string_to_operands(operand_str)
            
    def list_set(self, operand_list, secondary_operation = None):
        self._list = copy.deepcopy(operand_list)
        
        if secondary_operation:
            self.secondary_operation = secondary_operation
        
    def append(self, operand):
        self._list.append(operand)
        
    def append_left(self, operand):
        self._list.insert(0, operand)
        
    @classmethod
    def _inner_get_all_registers(cls, operand_list, register_set):        
        for operand in operand_list:
            if isinstance(operand, list):
                Operands._inner_get_all_registers(operand, register_set)
            elif operand in Operands.REGISTERS:
                register_set.add(operand)

    def get_all_registers(self):
        register_set = set()
        
        Operands._inner_get_all_registers(self._list, register_set)
        
        return register_set
    
    @classmethod    
    def get_all_registers_from_list(cls, lst):
        register_set = set()
        
        Operands._inner_get_all_registers(lst, register_set)
        
        return register_set
        
class Instruction(object):
    def __init__(self, mnemonic=None, operands=None):  
        
        if mnemonic == None or operands == None:
            mnemonic = Mnemonic()
            operands = Operands()
        
        self.mnemonic = mnemonic
        self.operands = operands



# Example Use

#instr0 = Instruction(Mnemonic("strgt.w"), Operands("r2, [r5, r6]!"))
#instr1 = Instruction(Mnemonic("bls"), Operands("sp"))
#instr2 = Instruction(Mnemonic("bl"), Operands("r6"))
#instr3 = Instruction(Mnemonic("mulscs.w"), Operands("r0, pc, r15, lsr #4"))
#instr4 = Instruction(Mnemonic("bhi.w"), Operands("#0x276c"))
#
#instrs = [instr0,instr1,instr2,instr3,instr4]
#
#i = 0
#for instr in instrs:
#    print("instr" + str(i) + ": ")
#    print("Mnemonic Name: " + str(instr.mnemonic.name))
#    print("Mnemonic Suffix: " + str(instr.mnemonic.suffix))
#    print("Mnemonic Condition: " + str(instr.mnemonic.condition))
#    print("Mnemonic Type: " + str(instr.mnemonic.mnemonic_type))
#    print("Operand List: " + str(instr.operands._list))
#    print("Secondary Operation: " + str(instr.operands.secondary_operation))
#    print("\n\n")
#    i+=1
