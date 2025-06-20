# GoRunas  
A utility for user impersonation without accessing LSASS memory.

# Usage

![image](https://github.com/namcuongq/gorunas/blob/main/images/1.png)

The tool can list available tokens which are running with the user you want to impersonate.

![image](https://github.com/namcuongq/gorunas/blob/main/images/2.png)

Example usage: 
```powershell
D:\Projects\Code\gorunas>gorunAs.exe exec DESKTOP-SIP4CNF/PC notepad.exe
                                _
        _ __   ___ __ _ _   _  __ _   / \   ___
   | '_ \ / _ |__  | | | |/ _  | / _ \ |__ \
   | |_) | (_) | | | |_| | | | |/ ___ \/ __/
   | .__/ \___/  |_|_.__/|_| |_/_/   \_\___|
        \___|  v1.0

```

![image](https://github.com/namcuongq/gorunas/blob/main/images/3.png)