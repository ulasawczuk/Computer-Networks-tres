# Computer-Networks-tres
This assignment includes two files, portScanner.cpp and puzzleSolver.cpp. The aim was to scna the open ports from a server, which later gave us instructions that we had to follow to get the numbers of the secret ports and a secret phrase needed to solve the final puzzle. To complie both file type and run "make" in terminal while being inside the directory.
First the portScanner.cpp scans for open ports. To use it type and run "./scanner <IP address> <low port> <high port>" in the terminal. The scanner will try all the ports in the given range and return the ones open i.e.: 
"OPEN PORTS: 
4047 4048 4059 4066 ".
Next we can use the puzzle solver to solve the ports instructions. Type and run "sudo ./puzzlesolver <IP address> <port1> <port2> <port3> <port4>", where the ports are the open ports returned by the scanner. Sudo is needed for a creation of a raw socket in the code. This will return solved ports separated by "-------------------" line. With each port we show the response from the port (starting with first puzzle) and the message we are sending it. 
