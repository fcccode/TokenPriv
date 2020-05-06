<<<<<<< HEAD
TokenExec 

Just trying to learn how windows access token works and what we can do with it. I think CreateProcessWithTokenW() is better then setting a thread process. You can use this tool to in red teaming engagements.

####What it can do?

You need SeImpersonateName Priv.
=======
# TokenExec 

Just trying to learn how windows access token works and what we can do with it. You can use this tool to in red team engagements.

#### What it can do?

You need SeImpersonateName Priv and Run as Elevated priv

1. Administrator -> SYSTEM or any user
2. SYSTEM -> basically any user
3. Don't try to get SERVICE account.

If you want SYSTEM then just use winlogon.exe process.

![](https://i.ibb.co/cycXVBK/Capture.png)
>>>>>>> fbaef3f5248e69a2ee91591c84738262cc066a8d
