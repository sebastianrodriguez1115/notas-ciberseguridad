# **The Great Disappearing Act**

First flag: THM{h0pp1ing_m4d}

1.  Email found in Fakebook, password made trying combinations

```
guard.hopkins@hopsecasylum.com
Johnnyboy1982!
```

Response:

```
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.12.3
Date: Sat, 13 Dec 2025 03:43:24 GMT
Content-Type: application/json
Content-Length: 264
Access-Control-Allow-Origin: http://10.64.189.234:13400
Vary: Origin
Access-Control-Allow-Headers: Authorization,Content-Type,Range
Access-Control-Allow-Methods: GET,POST,OPTIONS
Access-Control-Expose-Headers: Content-Range,Accept-Ranges
Connection: close

{"facility":"HopSec Asylumn","profile":{"role":"guard","username":"guard.hopkins@hopsecasylum.com"},"token":"{\"sub\": \"guard.hopkins@hopsecasylum.com\", \"role\": \"guard\", \"iat\": 1765597404}.281b07894670638e625fcd5e73184f55b87196755eb37c74ea6c37c5c2f08777"}

# Cambia por cada sesion
{"sub": "guard.hopkins@hopsecasylum.com", "role": "guard", "iat": 1765770609}.102e88647449ef773aeb7225400db7ce497919f74f00bfc8e88cabb3b8b20af4
```

# Notes

### **1. Unlock Hopper’s Cell**

Your escape begins in the Cells and Storage area. Hopper is locked inside, and the door is secured with a digital lock. Your first task is to access the cell controls and unlock his door. Once Hopper is free, you can begin moving toward the lobby.

```
Remove display none on the map and clicking the cell door.
```

### **2. Move Through the Lobby**

With the cell unlocked, head straight ahead into the lobby. This area connects the different blocks of the facility. Cameras are active, so stay alert. Your objective is to reach the Psych Ward entrance on the east side of the lobby.

### **3. Bypass the Psych Ward Keypad**

The Psych Ward is protected by a keypad system. You must identify the correct code or exploit the keypad to continue. Once the keypad is bypassed, you will gain access to the Psych Ward Exit hallway.

### **4. Reach the Main Corridor**

From the Psych Ward Exit you can move south and loop around into the Main Corridor. This is the final section of the escape route. The last challenge awaits here, and completing it will open the final exit door.

### **5. Escape the Facility**

Solve the final challenge in the Main Corridor and make your way toward the exit marked on the map. Once the door opens, Hopper is free, and the escape is complete.
