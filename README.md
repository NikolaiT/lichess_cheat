**README**

## Huge Update

Currently I am developing a proxy based cheat. My first attempt was to cheat by injecting some javascript into a running
lichess session with the browser console (inspect this element). But lichess adminstrators have proofed that it is too easy
to prevent such attempts to cheat, because they control the browsers javascript.

### Different approach

Now I follow a different approach. I am using the pretty nice proxy implemented in Python (https://github.com/abhinavsingh/proxy.py) to
modify all traffic according to lichess. Therefore we have different ideas:

+ Inject engine moves into websocket message frames. A typical websocket frame that is sent when moving looks like this:
```
WebSocket Frame: fin = 1, opcode = TEXT_FRAME, mask = 1, maskign_key: �0D�, payload_length = 182, 
payload = {"t":"move","d":{"from":"d7","to":"d5","b":1,"lag":43}}
```
+ Another idea is to inject some javascript into lichess javascript with the proxy and **start calulating the engine move as soon
as the opponent move was sent by the server**. Then the injected javascript shows the move in the browser session. Optionally, the
move is automatically made by the JS.
+ When lichess admins try to prevent this with some JS functionality, we will just delete the malicious javascript before it enters
the browser.
+ other ideas (probably more elegant)




## Old Cheat, don't read this! (for historical reasons)

Always use the newest javascript cheat version! This means the one with the highest number at the end!

Just paste the javascript in you browser console after running the python file on your localhost.


Cheaters will get detected pretty soon because of *https://github.com/ornicar/lila/commit/ce04144ee2393d06d510e2ac5cecea04d5c39f84*
Edit: No detecion of cheating anymore...
