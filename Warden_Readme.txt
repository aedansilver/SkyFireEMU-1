=Warden Daemon=

objective:
to make this anti-hack as it should be. think of any other anti-cheat software that is out,
it is not built into the core, it is stand alone and outside of the game itself.
hows this work? it processes sent/recieved packets between client and server, 
any that is sent malformed, it checks, if hack it kicks, if its unsure it flags for a review. 

in theory, what im trying to create is the same process... warden is posed between the 
authserver(authenication server) and the worldserver (realm server) and is completely stand alone.
warden is still attached to both the auth, and the realm server(s)
and scans the in/out going packets. as it should. "warden never sleeps".

we started with neo2003's mangos match:
(http://getmangos.com/community/topic/16244/warden-the-definitive-anticheat-system/)
and have been updating since.(credits to: Alexey, and leak for their work as well)
This was mostly a container daemon, this will as we evolve the code more progression is made, 
i've gotten through mostly all the changes to make this compatible with the core.
the initial goal: finish the basics(below), which means to get this system firing properly, 
and updated to the right packet/module offsets.
then to move deeper into the neccessary changes to make this fully a stand alone scanner.

im not concerned with the bugs atm... just the operations of this system...
bugs can be fixed, and remedied later.

TODO:

/*basics*/
fix the realm connection(single realm) to warden daemon.
add a delay to the warden client startup like for after the server loads.
(atm it's firing way to soon).
update any out of date packets.
update the offsets of the warden data modules for cata.
work on stability and cleaning of the codesytles (for better proformance)

/*itermediate*/
to fix for mutli-realm support. (much alike to the authserver)
to fix for other server systems. (*nix,mac etc)
to move the functions sololy to the warden system.

/*advanced*/
to update the packet read/send/return from client/server and add new kick/ban/flag(alert) methods.
prepare the server daemon for a parallel threading model (clustering).
create daemon Sql connection 
(if daemon is independant then needs its own connections, as well as hooks to realm/auth)

if any other devs see things, needing 2b added... changes can be made.

hopefully this gives everyone the development direction im trying to go.
ideas? suggestions? its an open project, so development discussion can be handled on forums. 
or irc.

Quote: "An idea is like a virus, resiliant, 
        highly contagious and the smallest seed of an idea can grow. 
        It can grow to define or destroy you."
        ~Inception.



