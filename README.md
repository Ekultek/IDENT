# IDENT
###### Ip address DENying Tool

_NOTE_: IDENT is a work in progress, I am stashing it here for storage

IDENT is an automated IP Address denying tool that will search a firewall log file and automate the task of denying unknown or unfiltered IP addresses depending on the amount of blacklists that the IP address is apart of. IDENT leverages [IPVoid](http://www.ipvoid.com) to check the amount of blacklists a provided IP address has. Features include:

 - Ability to decide how many blacklists should be passable
 - Automatic IP address lookup
 - Log file parsing
 
