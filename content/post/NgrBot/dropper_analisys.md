---
title: "NgrBot - Dropper analysis (Part 2)"
description: NgrBot - Dropper analysis (Part 2)

date: 2018-01-28T21:30:18+02:00

summary: "In the second delivery of NgrBot analisys we will take a close look of the malicious code that was unpacked by the Visual Basic executable in the previous post."

cardthumbimage: "/assets/NgrBot/cardthumbimage.jpg"

author:
  email: doop3lgang3r@gmail.com
  github: https://github.com/Doopel
  image:
  - /images/Doopel_Profile/dopelrIcon.png
  name:
  - Doopel

cardbackground: 'orange'
cardtitlecolor: 'white'

post_categories:
- Malware analysis

tags:
- Malware
- 2017

---

## Resume

Until now we have seen that the original Visual Basic executable just has injected a MZ executable inside a new process. And as we will see throw this post, it is a dropper/deployer that will deploy itself in the system and tries to infect as many as possible legit process running in the victim machine.

## Reversing unpacked executable

Before get into the static analysis of the sample, sometimes is really useful to take a look of its behaviour, so we will do a quick dynamic analysis of its execution. 

At this point if we execute “resume threat” or the extracted file that we get from the last post. It will create an independent process to inject malicious code inside “iexplorer” in order to bypass the firewall and connected itself to the IRC master chat. 

As we can see in the our favourite process monitor and network traffics analysis tools (eg. Process Hacker and Wireshark)

![monitor](/assets/NgrBot/Behaviour/monitor.png)

![traffic](/assets/NgrBot/Behaviour/traffic.png)

Thanks to the dynamic analysis now we know that we are dealing with a bot. Specifically,  one that communicates with its master throw a IRC channel. 

Welcome to the 80s :)

#### IRC botnet

An IRC botnet works as the following chart illustrate, the bot connects as a client to a chat and waits for instructions.

![botnet](/assets/NgrBot/IRC/botnet.png)

#### Internet Relay Chat (IRC) protocol

Immediately upon establishing a connection the client must attempt registration, without waiting for any banner message from the server.

Until registration is complete, only a limited subset of commands SHOULD be accepted by the server. This is because it makes sense to require a registered (fully connected) client connection before allowing commands such as JOIN, PRIVMSG and others.

The recommended order of commands during registration is as follows:

1. CAP LS 302 
2. PASS 
3. NICK and USER 
4. Capability Negotiation 
5. SASL (if negotiated) 
6. CAP END

#### Our IRC login case

In our case the client sends its user and  password message but unfortunately the server is not responding with the well come banner and the bot is not able to join the specific channel to receive commands.

For what we can extract from the traffic captured before we know that

* the username and the nick used in the chat are generated strings by the malware which uses the information extracted from the infected system to create an unic ID.  The nicknme is something like **n{"system language"|"windows vesion"}"username"** (eg, n{ES|W7u}dsiqdxi) and the username probably is a random string (eg, dsiqdxi). 

* the password used to login into the chat is **ngrBot**.

With this information we could craft our own client in order to log into the botnet a interact with it, but as we saw the IRC server is down. So from here, we only can keep looking into the code of our sample to get more information.

## Reversing unpacked executable in IDA

At this point we know what is going to do the malicious code, we have it dumped and we do not require from the parent executable any more to launch the malware. But looks quiet interesting to know how it is able to create an independent process and make its self persistent in the infected system.

Let’s take a look to the assembly code in IDA :)

Father Behaviour Resume:

* Decode part of its .data section data.
* Gets drive information possible Anti-VB  possible Anti-VB
* Tries to open communication mutex 
* Make persistent
* Launch deployed executable

#### Decryption .data

At the beginning of its execution it decrypts some important strings from its .data section.

![string_decryptor](/assets/NgrBot/unpacked/string_decryptor.png)

From the first decryption function really interesting strings provides us an over view of which capabilities it has:

* Antivirus detection
* IRC commands: USER, NICK, JOIN, PART, PRIVMSG, QUIT, PONG, PING, PRIVMSG 
* Browsers injection:  i e x p l o r e . e x e     f i r e f o x . e x e

* Registers (persistent):  
        ◦ S o f t w a r e \ M i c r o s o f t \ W i n d o w s \ C u r r e n t V e r s i o n \ R u n   
        ◦ S o f t w a r e \ M i c r o s o f t \ W i n d o w s \ C u r r e n t V e r s i o n \ P o l i c i e s \ S y s t e m  
* Auto Update
* Hijacking 
* DDOS: SYN flood, UDP flood.Propagation:
        ◦ USB
        ◦ Mail
        ◦ Malicious HTML injection
        ◦ FTP brute force
        ◦ DNS poisoning
        ◦ Network Shared folder
* Credential stealing

And the second one get us what looks like the bot commands used to communicate with its master:

* :!v
* :!rc
* :!die
* :!rm
* :!s
* :!us
* :!stop
* :!stats
* :!logins
* :!rs0
* :!speed
* :!m
* :!j
* :!p
* :!dl
* :!msn.set
* :!msn.int
* :!http.set
* :!http.int
* :!http.inj
* :!mdns
* :!vs
* :!up
* :!slow
* :!mod
* :!rs1
* :!udp
* :!ssyn


## Get drive information

Coming up next, it checks the C:\ disk properties in order to detect if it is being executed in a virtual environment.

To check it, it uses two functions “CreateFileA” to get C:\ handler and “DeviceIOControl” to fetch the device factory name.

* CreateFileA will return in this case the handler x94 which will be saved in eax. Arguments:

![disk_proper](/assets/NgrBot/unpacked/Sys_info/disk_proper.png)
![disk_proper_2](/assets/NgrBot/unpacked/Sys_info/disk_proper_2.png)

* DeviceIOControl: using the taken handler it obtains the hard disk’s name which is saved in “OutBuffer”:0018F864.

![disk_proper_dump](/assets/NgrBot/unpacked/Sys_info/disk_proper_dump.png)

#### Open Mutex

It tries to open a Mutex which will be uses later to communicate with its “independent son”. At the first execution it will not exist. It will be used by his mutant son.


#### Make itself persistent

It copies itself into **C:\Users\”username”\AppData\Roaming** , registers itself in **\Softwaer\Microsoft\CurrentVersion\Run** to be executed automatically and launches the dropped/copied executable.

![persistence](/assets/NgrBot/unpacked/persistence/persistence.png)

#### Launch deployed executable

After the deployment stage it launch the dropped replica stored in **“AppData\Romaing”** using a particular flag **CREATE_NEW_CONSOLE** of the CreateProcessW API call that will execute it as a new process tree.

![CreateProcess](/assets/NgrBot/unpacked/lauch/CreateProcess.png)

**Note:** The new process has a new console, instead of inheriting its parent's console (the default).
To keep tracking the execution we want to attach to the new process but unfortunately there are to factors that make it a little bit tricky:

* It has a custom values in StartInfo&ProcessInfo structures

![process_conf](/assets/NgrBot/unpacked/lauch/process_conf.png)

* Once the CreateProcess is called we will not be able to attach properly to it. To attach to it I just stopped fathers execution just before CreateProcessW call and modified the binary (Xmbmbj) manually making a infinite loop in its first jump instruction.

In this particular case he first jump is **“jz eip+95” (74 jz opcode, 5F = 95)** and we want to loop infinite times over that instruction that means we want to jump to **“eip-4” (FE = -4)**.  

![loop](/assets/NgrBot/unpacked/lauch/loop.png)

Now that we are attached to the new process we only need to restore the original jump instruction directly in the debugger a continue the execution (F9) until the end of father’s process and start debugging his son which will take a different execution flow.

## Reversing deployed executable

It will follow the same execution flow as his father until deployment_launcher function where his father dies after it launches his son.

![init](/assets/NgrBot/deployed/init.png)

Son’s main mission is to inject malicious code inside legit processes. To accomplish it, it does the following actions:

#### Preliminary set-up

1. It creates a file map to store some useful information.
    1. Create mutex
![create_mutex](/assets/NgrBot/deployed/setup/create_mutex.png)
    2. CreateFileMap
![createFileMap](/assets/NgrBot/deployed/setup/createFileMap.png)

        **Note:** If hFile is INVALID_HANDLE_VALUE, the calling process must also specify a size for the file mapping object in the dwMaximumSizeHigh and dwMaximumSizeLow parameters. In this scenario, CreateFileMapping creates a file mapping object of a specified size that is backed by the system paging file instead of by a file in the file system.
        ![mutant](/assets/NgrBot/deployed/setup/mutant.png)
    3. MapViewofFile (Maps a view of a file mapping into the address space of a calling process)
        ![mapViewofFile](/assets/NgrBot/deployed/setup/mapViewofFile.png)
        1. Starting address of the mapped view:
        ![start_address](/assets/NgrBot/deployed/setup/start_address.png)
        2. Values written:
        ![values](/assets/NgrBot/deployed/setup/values.png)
        3. Flag as running
        ![flag](/assets/NgrBot/deployed/setup/flag.png)

#### Launch iexplorer

At this point, it tries to launch "Internet Explorer" to be sure that it is able at least inject its malicious code inside a running/legit process.

It searches the path of internet explorer and launch it:

![iexplorer_func](/assets/NgrBot/deployed/explorer/iexplorer_func.png)

* SHGetSpecialFolderPathW
![SHGetSpecialFolderPath](/assets/NgrBot/deployed/explorer/SHGetSpecialFolderPath.png)

* PathAppendW
![PathAppendW](/assets/NgrBot/deployed/explorer/PathAppendW.png)

* CreateProcessW
![CreateProcessW](/assets/NgrBot/deployed/explorer/CreateProcessW.png)

#### Malicious code injection

It searches for all the process running under WoW64 to infect them. It just has load iexlorer to be sure to find some victim but it will do the same to all the possibles targets. In my case the first process it detects is iexplorer.exe with handler **0x10C**. The way to infect a process and execute the code is:

* Loads in a remote process’ memory the input parameters that are going to be used by the malicious code:

    * VirtualAllocEx:
![VirtualAllocEx](/assets/NgrBot/deployed/injection/VirtualAllocEx.png)
    * WriteProcessMemory
![WriteProcessMemory](/assets/NgrBot/deployed/injection/WriteProcessMemory.png)
![WriteProcessMemory_2](/assets/NgrBot/deployed/injection/WriteProcessMemory_2.png)

* To copy the malicious code it does the same, in this case:
    * VirtualAllocEx:
![VirtualAllocEx_2](/assets/NgrBot/deployed/injection/VirtualAllocEx_2.png)
    * WriteProcessMemory
![WriteProcessMemory_3](/assets/NgrBot/deployed/injection/WriteProcessMemory_3.png)
![WriteProcessMemory_4](/assets/NgrBot/deployed/injection/WriteProcessMemory_4.png)

* Now it already has infected his target but to execute that code  it creates a remote thread in the infected process to launch the malicious code selecting as “StartAddress” the startAddress of the malicious code (010BC374) and as “lpParameter the section that was stored before (EF0000).
![remote_thread](/assets/NgrBot/deployed/injection/remote_thread.png)


#### Dumping iexplore injected code

At this point, "Iexplorer" has been infected and the real malicious code is running freely in the victim machine. The next step is to dump the MZ store in “iexplorer” memory and continue our investigation. To dump it I just used the tool “ProcessHacker”.

![dump](/assets/NgrBot/deployed/dump.png)

## Conclusion

In this post we have seen how the malware has deployed and made itself persistent in the victim system and a interesting technique to inject malicious code inside legit programs unlinking the original malware process tree.

In the following and last post we will take a look into the injected code a we will be able to confirm the malware capabilities that we have guessed from the decoded strings.


## Tools

* OllyDbg
* ProcessHacker
* IDA pro
* Wireshark


