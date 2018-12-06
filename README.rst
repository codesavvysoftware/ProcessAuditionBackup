http://www.theron-library.com/index.php


Command Examples::

    {"command":"blah"}
    {"command":"ping"}
    {"command":"add rules"}
    {"command":"add rules", "content":[]}
    {"command":"add rules", "content":["wrong"]}
    {"command":"quit"}
    {"command":"put rules", "content": [{"identification": "0", "specs": [{"filename" : "powershell.exe"}] }, {"identification": "1", "specs": [{"filename" : "reg.exe"}]}, {"identification": "2", "specs": [{"filename" : "vssadmin.exe"}]}, {"identification": "3", "specs": [{"filename" : "ntdsutil.exe"}]}, {"identification": "4", "specs": [{"filename" : "regsvr32.exe"}]}, {"identification": "5", "specs": [{"filename" : "mshta.exe"}]}]}
    {"command":"put rules", "content": [{"identification": "5", "specs": [{"filename" : "mshta.exe"}]}]}


StdAfx.h
--------

In this Solution the conventional naming is ignored, preferring "Precompiled" in favor of some archaic Microsoft-ism.

`StdAfx.h on PVS-Studio Blog <https://www.viva64.com/en/b/0265/#ID0ET3DI>`_


ToDo:
-----

- Diffie-Hellman Key Exchange to establish an encrypted channel.
  - https://security.stackexchange.com/questions/45963/diffie-hellman-key-exchange-in-plain-english#45971
- "set interval" command


Cross-Platform
--------------
Cross-Platform will require (among other things):
- Alternative for Crypto (current the WinAPI CNG functionality is used).
  - One possible alternative is `Crypto++ <https://www.cryptopp.com/>`_
