# Pwnation.github.io

This is the repository of the blog pwnation.github.io.  
We will blog stuff about CTFs, some little research we do in our free time and, in general, whatever we think is interesting.


## fast Instructions to get it working locally
You need to have python installed to install a custom pygment lexer.
```
$ sudo pacman -S python2 hugo

$ git clone git@github.com:Pwnation/radare2-pygments-lexer.git
$ python radare2-pygments-lexer/setup.py install

$ git clone git@github.com:Pwnation/Pwnation.github.io.git pwnation
$ sudo python setup.py install

$ cd pwnation
$ hugo server --ignoreCache --buildFuture
```
