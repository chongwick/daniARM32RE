# symGen
Symbolic Peripheral Value Generator (ARM 32-bit)

A branch-based fuzzer using Capstone and Z3 Theorem Prover. Finds conditional branches in stripped binary before tracing back to critical reads from peripheral memory. Uses symbolic execution techniques to create execution path models. Inputs these models to an SMT solver to generate values which can then be fed to an emulator to increase coverage while preventing the processor from entering a broken state.
