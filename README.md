# TokenExec 

Just trying to learn how windows access token works and what we can do with it. I think CreateProcessWithTokenW() is better then setting a thread process. You can use this tool to in red teaming engagements.

#### What it can do?

You need SeImpersonateName Priv.
Run as Elevated priv

1. Administrator -> SYSTEM or any user
2. SYSTEM -> basically any user
3. Don't try to get SERVICE account, you know it won't work (Soon going to add NamedPipe)

If you want SYSTEM then just use winlogon.exe process (Object right).

#### How it works?
Get token handle -> duplicated it -> create process with that token.
