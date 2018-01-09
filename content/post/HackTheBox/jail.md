---
title: "HackTheBox - Jail"
description: ""

date: 2018-01-06T17:56:18+01:00
publishdate: 2018-01-06T17:56:18+01:00

summary: ""
cardthumbimage: "/assets/HackTheBox/title.png"

author:
  email: tzaoh1@gmail.com
  github: https://github.com/tzaoh
  image:
  - /images/avatar-64x64.png
  name:
  - Tzaoh

cardbackground: 'orange'
cardtitlecolor: 'white'

post_categories:
- CTFs

tags:
- CTF
- HackTheBox

---

![Jail Description](/assets/HackTheBox/Jail/1-inst_prof_description.png)

#### Introduction

Como entrenamiento antes de apuntarme al [OSCP][1] decidí empezar a utilizar la plataforma de [HackTheBox][2]. Es una plataforma gratuita (aunque tiene una vía de financiación dando ciertos beneficios a usuarios VIP :blink: ) donde ponen a disposición diferentes máquinas para vulnerar. 

Este post es sobre una de esas máquinas: Jail. IP 10.10.10.34.

Empezamos haciendo un escaneo rápido para ver que servicios tenemos entre mano

```sh
# nmap -sS -sV -Pn -n 10.10.10.34 -oN jail_normal

Starting Nmap 7.60 ( https://nmap.org ) at 2018-01-07 19:03 CET
Nmap scan report for 10.10.10.34
Host is up (0.10s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 6.6.1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS))
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs_acl 3 (RPC #100227)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.21 seconds

```

Mmmh, vale. Tiene un servidor web, un servicio SSH para conectarse seguramente después de conseguir alguna credencial y un servicio NFS. Curioso.

Vamos a empezar con lo fácil.


#### Servicio WEB

¿Qué nos dice el servicio web? Después de echar un vistazo a la web principal y ver que no nos van a dar nada de gratis:
![](/assets/HackTheBox/Jail/1-main_webpage.png)

Hacemos algunas ejecuciones con `dirbuster` y `dirb` y obtenemos los siguientes subdirectorios.
```bash
/
/icons/
/icons/small/
/jailuser/
/jailuser/dev/
/cgi-bin/
/jailuser/dev/jail
/jailuser/dev/compile.sh
/jailuser/dev/jail.c
```

Interesante, tiene un código fuente escrito en C, su binario compilado y su línea de compilación. He aquí un fragmento del archivo [jail.c](/assets/HackTheBox/Jail/jail.c) que contiene un buffer overflow clásico.
{{< highlight c "hl_lines=9" >}}
int auth(char *username, char *password) {
    char userpass[16];
    char *response;
    if (debugmode == 1) {
        printf("Debug: userpass buffer @ %p\n", userpass);
        fflush(stdout);
    }
    if (strcmp(username, "admin") != 0) return 0;
    strcpy(userpass, password);
    if (strcmp(userpass, "1974jailbreak!") == 0) {
        return 1;
    } else {
        printf("Incorrect username and/or password.\n");
        return 0;
    }
    return 0;
}
{{< /highlight >}}

Además si nos fijamos en el [script de compilación](4), nos damos cuenta de que el código se está compilando con el flag `execstack`, lo cual nos indica que podemos utilizar la misma pila para ejecutar instrucciones una vez desbordado el buffer que hemos indicado anteriormente.
{{< highlight sh "hl_lines=1" >}}
    gcc -o jail jail.c -m32 -z execstack
    service jail stop
    cp jail /usr/local/bin/jail
    service jail start
{{< /highlight >}}

Si nos fijamos también un poco más abajo del código fuente del programa
{{< highlight c "hl_lines=1" >}}
    port = 7411;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);
{{< /highlight >}}

vemos que el programa esta pensado para funcionar en el puerto 7411. Podemos comprobar que está efectivamente activo conectándonos directamente desde netcat, por ejemplo.
{{< highlight c "hl_lines=4" >}}
nc -vv 10.10.10.34 7411
Warning: Inverse name lookup failed for `10.10.10.34'
10.10.10.34 7411 (daqstream) open
OK Ready. Send USER command.
{{< /highlight >}}

Asique ya sabemos que existe un programa vulnerable escuchando en el servidor que queremos atacar. Ahora necesitamos desbordar la pila y enviar una `shellcode` para usar 

Vale, ¿qué necesitamos exactamente para desbordar la pila?


Vale, ya tenemos una shell sin privilegios. ¿Cómo podemos aumentarlos? Es aquí donde entra el servicio NFS que hemos descubierto en el escaneo

#### Servicio NFS



Recuerdo que NFS se usa para compartir unidades por red y poco más. Vamos a investigar un poco sobre estas unidades.

Parece que nmap tiene algunos scripts para ellas. [nfs-showmount][3], por ejemplo, te muestra las rutas compartidas.
```sh
# nmap -sS --script=nfs-showmount 10.10.10.34 -oN nfs_service

Starting Nmap 7.60 ( https://nmap.org ) at 2018-01-07 19:12 CET
Nmap scan report for 10.10.10.34
Host is up (0.092s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
111/tcp  open  rpcbind
| nfs-showmount: 
|   /opt *
|_  /var/nfsshare *
2049/tcp open  nfs

Nmap done: 1 IP address (1 host up) scanned in 14.15 seconds
```

Vamos a intentar montarlas en local.
```sh
# mount -t nfs 10.10.10.34:/opt /mnt/opt
# mount -t nfs 10.10.10.34:/var/nfsshare /mnt/nfsshare
# ls -R /mnt/{opt,nfsshare}                                                                            
ls: no se puede abrir el directorio '/mnt/nfsshare': Permiso denegado
/mnt/opt:
logreader  rh

/mnt/opt/logreader:
logreader.sh

/mnt/opt/rh:
```

What is in `logreader.sh`?
```bash
#!/bin/bash
/bin/cat /home/frank/logs/checkproc.log
```

The only thing we get from this for the moment is a path inside of the machine an a username.

#### References and tools used

[1]: https://www.offensive-security.com/information-security-certifications/oscp-offensive-security-certified-professional/
[2]: https://www.hackthebox.eu
[3]: https://nmap.org/nsedoc/scripts/nfs-showmount.html
[4]: /assets/HackTheBox/Jail/compile.sh
