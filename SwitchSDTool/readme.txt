----- How to dump NSPs from your SD card for the First time. -----

Step 1: Put your Switch into Airplane mode and remove ALL wifi connection profiles. (Safety measure to avoid a potential ban.)
Step 2: Follow the tutorial at https://gbatemp.net/threads/backup-restore-your-nand-get-your-biskeys-tseckeys-keys-txt-guide.513386/ to dump your nand, keys.txt and biskey dump.
Step 3: Restore the nand back up, if you have not already done so via above tutorial following the dumping of biskey.txt and keys.txt. (Safety measure to avoid a potential ban.)

Step 4: Grab Hac Disk Mount from https://switchtools.sshnuke.net/
Step 5: Power off your switch. Mount the SD card from your switch to your PC.
Step 6: Open up hac disk mount with Administrator Priveleges. (This is mandatory in order to install the Virtual Drive driver.).
Step 7: Open up rawnand.bin in hac disk mount.
Step 8: Double click on PRODINFO
Step 9: Open up biskey.txt and copy in the Crypto and Tweak keys from Bis Key 0, then click on Test. Make sure the result says Entropy OK.
Step 10: Click on Browse in Dump to File, and browse to the location where you extracted this tool to.
Step 11: Click on Start.

Step 12: Click on the X. we are done with PRODINFO.
Step 13: Double click on System.
Step 14: Copy in the Crypto and Tweak keys from Bis Key 2, the click on Test. Make sure the result says Entropy OK.
Step 15: Install the Virtual Drive driver.  (If it errors, you need to reopen Hac disk mount with administrator priveleges.)
Step 16: Click on Mount.

Step 17: Copy keys.txt from the SD card to where you extracted this tool.
Step 18: Open the tool. (If it errors, make sure you have installed .NET Framework 4.7.1)
Step 19: Click on Select SD Folder. Choose the Drive that the SD is mounted to.
Step 20: Click on Select System Path. Choose the Drive letter you mounted the SYSTEM partition to. (A drive by default.)
Step 21: Click on Select Decryption Path. Choose where you want the decrypted NCAs to reside.
Step 22: Click on Select NSP Output Path. Choose where you want your NSP dumps to be saved.
Step 23: Google for eticket_rsa_kek.
Step 24: Paste the results in the text field that says "Replace me with the actual eticket_rsa_kek.".
Step 25: The Log should say "ETicket RSA KEK is correct.". If it does not, go back to step 22 and try harder.

Step 26: Click on "Find SD Key".  The log should say "SD Key Loaded".
Step 27: Click on Load RSA KEK. The log should have two entries. "E-Ticket RSA Key Encryption Key loaded successfully" and "RSA Key extracted successfully from PRODINFO.bin".

Step 28: Click on Extract Tickets. Log should say "Dumping Tickets" followed shortly by "Done. x Tickets dumped".
Step 29: Click on Decyrpt NCAs. Log should show a bunch of "Processing --file--.nca - Decrypting, Done. Verifying, Verified.  (May start with Joining, Done).
Step 30: Click on the Language Tab.
Step 31: Click on your preferred language, and move it to the top by click on Move Up.  Repeat for 2nd preference.
Step 32: Click on the Games Tab, then Click on Parse NCAs.  This should finish, and all of your games present on the SD card should be listed, along with any Updates and DLC.
Step 33: Click on Pack ALL NSPs to pack everything, or select a game, and click on Pack Selected NSP to pack that NSP only.
Step 34: Close the tool.
Step 35: Unmount the SYSTEM partition and close hac disk mount.
Step 36: Unmount the SD card and put it back into your switch.

----- How to Dump NSPs from new purchases / updates since last dumping. -----

Step 1. Dump your nand, following the guide at https://gbatemp.net/threads/backup-restore-your-nand-get-your-biskeys-tseckeys-keys-txt-guide.513386/ (Provided you saved biskey and keys.txt, you won't need to redump those.)
Step 2: Power off your switch. Mount the SD card from your switch to your PC.
Step 3: Open up hac disk mount with Administrator Priveleges. (This is mandatory in order to install the Virtual Drive driver.).
Step 4: Open up rawnand.bin in hac disk mount.
Step 5: Double click on System.
Step 6: Copy in the Crypto and Tweak keys from Bis Key 2, the click on Test. Make sure the result says Entropy OK.
Step 7: Click on Mount.
Step 8: Open the tool.
Step 9: Click on "Find SD Key".  The log should say "SD Key Loaded".
Step 10: Click on Load RSA KEK. The log should have two entries. "E-Ticket RSA Key Encryption Key loaded successfully" and "RSA Key extracted successfully from PRODINFO.bin".
Step 11: Click on Extract Tickets. Log should say "Dumping Tickets" followed shortly by "Done. x Tickets dumped".
Step 12: Click on Decyrpt NCAs. Log should show a bunch of "Processing --file--.nca - Decrypting, Done. Verifying, Verified.  (May start with Joining, Done).
Step 13: Click on the Games Tab, then Click on Parse NCAs.  This should finish, and all of your games present on the SD card should be listed, along with any Updates and DLC.
Step 14: Click on Pack ALL NSPs to pack everything, or select a game, and click on Pack Selected NSP to pack that NSP only.
Step 15: Close the tool.
Step 16: Unmount the SYSTEM partition and close hac disk mount.
Step 17: Unmount the SD card and put it back into your switch.