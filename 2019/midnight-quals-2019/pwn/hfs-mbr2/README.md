# HFS-MBR2

(The file is the same as re chall HFS-MBR)

* Split the img file at the offset 0x10000 and get the last one for better view in IDA
* The main loop is at 0x109b and you can find that the pointer to input buffer will decrease if you input '\r'
* No check for lower bound of input buffer, so it results in buffer underflow
* Change the filename "flag1" to "flag2"
* Change the jump table for switch in parsing command and make it call the function again at 0x104f used to get flag1
* As the filename has been changed, so we can get flag2
