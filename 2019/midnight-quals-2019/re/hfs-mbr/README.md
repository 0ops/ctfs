# HFS-MBR

* Rebase the img to 0x7800 and you will find the code that checks password at 0x7e37 by debugging
* Read the asm code and find that there is a jump table for switch at 0x8026
* The input of switch is the char given by user and it's easy to infer the right password "sojupwner"
