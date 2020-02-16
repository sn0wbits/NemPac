    #####     ###                                #########
    ######    ###                                ###    ###
    ### ###   ###	######   ####     ####   ###     ###   ###         #######
    ###  ###  ###	###      #####   #####   ###    ###  ### ###     ###
    ###   ### ###	#####	 ### ##### ###   ########   ###   ###   ##
    ###    ######	###	 ###	   ###   ###        #########    ###
    ###     #####       ######   ###       ###   ###        ###   ###      #######


Network Mapping and Packet Capture and Analysis
--------------------------------------------------------------------------


    Table of Content
    ------------------
    0.......INTRO
    1.......MODULES
     1.0....NETWORK MAPPER
     1.1....PACKET CAPTURE AND ANALYSIS
     1.2....AI COMPARISON
 
 
 
 
 
1.0 NETWORK MAPPER
 
 By using the CIDR notation the netmask is generated. By flipping the CIDR notation we can also generate the wildcard, then use this to calculate the IP addresses, used for scanning using the following formulas:

Common CIDR notations:
	/24 = 11111111 . 11111111 . 11111111 . 00000000
	        255    .   255    .   255    .    0
	The wildcard would then be:
	/8  = 00000000 . 00000000 . 00000000 . 11111111
	         0     .    0     .    0     .   255
	
	/16 = 11111111 . 11111111 . 00000000 . 00000000
		255    .   255    .    0     .    0
	The wildcard would then be:
	/16 = 00000000 . 00000000 . 11111111 . 11111111
	         0     .    0     .    255   .   255

	/8  = 11111111 . 00000000 . 00000000 . 00000000
	        255    .    0     .     0    .    0
	The wildcard would then be:
	/24 = 00000000 . 11111111 . 11111111 . 11111111
	         0     .   255    .    255   .   255

