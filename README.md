## TCP/IP Chatroom
The server (listener socket) binds itself to port 3490 where it polls for clients (users) to connect.
In order to connect to the chatroom the client must run the ./client program followed by the hostname of the server.
```

e.g   ./client user-hostname

```
All the testing was done by using the same IP address on the same computer, with the server and clients executed in separate terminals.
"virtually all machines implement a loopback network “device” that sits in the kernel and pretends to be a network card"-[Beej's Guide to network programming](https://beej.us/guide/bgnet/html/)

## Client Capabilities
* Allow user to register to on the server
* Allow user to login to the server, by previously setting accordingly the function password_storage and changing accordingly the login_users global varible
* User can log out by closing the program (Ctrl + c)
* When a user is logged in, she/he receives a list with all current on line users
* When a user is logged in or logged out all on line users receive a message "user has entered the chat" or "user has left the chat" 
* When a user is not a logged in user it must provide a user,password name where where the first word before "," will be its username, username cannot include "," 
* The same username cannot be used by multiple user and a warning will appear "username is already used" 
* When a registered user is logged out the same username can be used by another user, but the names of the logged in users (defined in password_storage) cannot be reused.
* In order to log in the user gives the following commands 
```

login (enter)
user,password (enter)

```

* In order to register the user gives the following commands
```

register (enter)
user,password (enter)

```
After each failing try to register or log in the user must close the program and run again.
If the user does not provide the right format of user,password a message is printed.


## Server Capabilities
When the ./server program is executed it asks for the maximum number of users the chatroom can have.
If the number provided is smaller than the number of login_users (defined in password_storage) a message is thrown and the program exits.
The number max users is always login_users+registered users, so if max users is 4 and login_users are 3 then only one registered user is allowed to enter.
If more users try to connect it gives an error of max chat users.
If a logged in user tries to connect more than once it gives an error of password already used.




