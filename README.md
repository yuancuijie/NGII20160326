# NGII20160326
轻量级IPv6环境下无线传感器网络身份认证体系研究
This file is about Sood Auth
	本次程序主要实现了Sood等人在2011年发表于Computer Network的一篇文章，
协议只利用Hash函数设计实现了一个高效轻量级的三方互认证协议。本程序模拟
模拟实现了其中的改进版本，具体协议的详细内容见作者原文。《An efficient
and security dynamic identity based authentication protocol for multi
-server architecture using smart cards》。
URL
<Go to ISI>://WOS:000300862900023
http://www.sciencedirect.com/science/article/pii/S1084804511002244


程序思想：
	利用sock编程模拟3个进程分别实现用户，服务提供者，控制中心，三个实体。
通过sock的通信过程模拟三个实体通信。加密算法库使用ARM公司负责维护的mbedt
-lsSSL库，主要使用了mbedtls-ssl库中的MD5-Hash函数，和随机数产生模块。

程序运行方法：
    编写环境：Ubuntu 16.04.1 LTS 
    编译器  ： GCC 
    程序库依赖 ：mbedtls-ssl C语言基本程序库

    1.首先检查自己的linux机器上是否安装mebdtls，一般情况下是没有，可以去
mbedtls的官网去下载 https://tls.mbed.org/。

    2.拷贝到自己用户的主目录下,执行如下shell命令

    # tar xzvf mbedtls-2.3.0-apache.tgz
    # cd mbedtls-2.3.0/
    # make
    # make install 

    3.编译文件

    # make Server
    # make CtlCenter
    # make SmartCart

    4.运行程序，这里需要注意启动流程，首先启动Server服务器，然后启动CtlCenter
中心，最后启动SmartCart程序。Server程序和CtlCenter程序会自己为SmartCart程序
提供服务。
	开启一个终端执行
	# ./Server
	再次开启一个终端执行
	# ./CtlCenter
	再次开启一个终端执行 注意：这里开启了三个终端
	# ./SmartCard

	5.在SmartCard程序中注册用户，需要值得注意的是本程序的SID计算量是由Hash
IP地址：端口号得到的，故程序输入为 your IP Address：port ，本程序里输入的为
127.0.0.1:9737,即本机IP的9737端口

本程序中已有一个以注册用户，可以帮助你验证登录部分
user_ID: cookie
passwd : 123456
SID    : 127.0.0.1:9737

需要注意的是Smartcard程序中的输入最好一次输入正确，如果输入不正确，重启程序输
入，输入这里我做的不好。

Made by CookieDemo
