# Frida

## Task 0 : Frida Installation

Frida consists of a server and a client. You need to set up a client for your host (e.g., your PC) and set up a client for your android device.

### Client Installation

The client recommended can be installed using pip:

```bash
# It's recomended to use python3
python3 -m pip install frida-tools
```

Check your installtion

```bash
# for Windows users, restart your terminal
frida --version
```

### Server Installation 

The server can be downloaded from [Frida's Github Release Page](https://github.com/frida/frida/releases)

Download the frida server for your specific android platform (e.g., arm, arm64, x86, x86_64)

- [frida-server-16.0.11-android-arm.xz](https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-android-arm.xz)
- [frida-server-16.0.11-android-arm64.xz](https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-android-arm64.xz)
- [frida-server-16.0.11-android-x86.xz](https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-android-x86.xz)
- [frida-server-16.0.11-android-x86_64.xz](https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-android-x86_64.xz)

For example, download and extract Fridaextractedthe emulator device ADB server for x86_64:

```bash
# using wget to download, you can also download from your browser
wget https://github.com/frida/frida/releases/download/16.0.11/frida-server-16.0.11-android-x86_64.xz 

#extract it using xz
# for windows users, you can use gitbash all wsl, which contains xz command.
xz -d frida-server-16.0.11-android-x86_64.xz

# rename the extrated file to frida-server 
mv frida-server-16.0.11-android-x86_64 frida-server
```

Then you need to push the `frida-server` to your device. Launch your android device and use `adb` to push files.

```bash
# before executing commands below, Make sure that your emualtor has launched
adb push frida-server data/local/tmp/				# push to your device
adb root	
adb shell “chmod 755 data/local/tmp/frida-server”	# make it executable 
```

### Check Installation

Firstly, launch your FridaUSB-server on your device

```bash
adb shell "data/local/tmp/frida-server &"
```

Then, open a new terminal (do not close the original one): 

```bash
frida-ps -U			# option "-U" means to show ps information of the attached usb device 
```

You should see something like this: 

```bash
$ frida-ps -U
 PID  Name
----  ---------------------------------------------------
2372  Calendar
2031  Clock
2395  Contacts
2440  Email
2483  Messaging
2117  Phone
1907  Settings
2783  adbd
2664  android.ext.services
1429  android.hardware.audio@2.0-service
1536  android.hardware.biometrics.fingerprint@2.1-service
1430  android.hardware.camera.provider@2.4-service
...
```

## Task 1 : Hook a function

In this task, we will provide you with an example `hookme.apk`. You need to hook the `onClickMe` method to force the app to print "Succeeded". This task is simple and we will provide step-by-step tutorials.

#### Step1: Get and launch hookme.apk

Please see the MainActivity of the app, If you want to print "Succeeded.", you need to make `this.m == 0`. This can be done by hooking the `onClickMe`.

```java
public class MainActivity extends AppCompatActivity {
    Button clickMeButton;
    int m;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        m = 1000;

        clickMeButton = (Button) findViewById(R.id.clickMeButton);

    }

    public void onClickMe(View v){
        if (this.m == 1000) {
            Toast.makeText(this, "Failed.", Toast.LENGTH_LONG).show();
        }
        if (this.m == 0) {
            Toast.makeText(this, "Succeeded.", Toast.LENGTH_LONG).show();
        }
    }
}
```

Install and launch hookme.apk:

```bash
adb install hookme.apk
adb shell am start -n com.example.hookme/.MainActivity
```

Then the app will be launched. If you click the button it should always print "Failed." .

#### Step2: Launch Frida-server 

If the frida-server launched in **Task 0** is still running, skip the step 2.

else:

```bash
adb shell "data/local/tmp/frida-server &"
```

#### Step3: Write client scripts to achieve hooking

Create and open `example.py`.You need to import the corresponding package at the very beginning.

```python
import frida, sys
```

Define a message receiver for receiving messages from server:

```python
def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)
```

Define the javascript code used by server to hook `onClickMe`.  You can see this script set `this.m = 0` before the original `onClickMe` is invoked, so the app will print "Succeeded.".

```python
jscode = """
Java.perform(() => {
  // Function to hook is defined here
  const MainActivity = Java.use('com.example.hookme.MainActivity');

  // Whenever button is clicked
  const onClick = MainActivity.onClickMe;
  onClick.implementation = function (v) {
    // Show a message to know that the function got called
    send('Trigger onClickMe! Hooking...');
    this.m.value = 0;
    send('Value of m is changed to ' + this.m.value + '.')

    send('Calling original onClickMe method')
    onClick.call(this, v);

    send('Hook Done');
  };
});
"""
```

Attach the script to the running app: 

```python
process = frida.get_usb_device().attach('HookMe')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

The whole script is below . However, We recommended you to code it line-by-line to get a better understanding.

```python
import frida, sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(() => {
  // Function to hook is defined here
  const MainActivity = Java.use('com.example.hookme.MainActivity');

  // Whenever button is clicked
  const onClick = MainActivity.onClickMe;
  onClick.implementation = function (v) {
    // Show a message to know that the function got called
    send('Trigger onClickMe! Hooking...');
    this.m.value = 0;
    send('Value of m is changed to ' + this.m.value + '.')

    send('Calling original onClickMe method')
    onClick.call(this, v);

    send('Hook Done');
  };
});
"""

process = frida.get_usb_device().attach('HookMe')
script = process.create_script(jscode)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

#### Step4: Run the scripts 

Make sure your Frida server is running. Then you can run the python file:

```bash
python3 example.py
```

Now, if you click the button, you will get "Succeeded.", and you will get these output lines from recommended extracted the emulator device ADBUSB,example.py:

```
$ python example.py
[*] Trigger onClickMe! Hooking...
[*] Value of m is changed to 0.
[*] Calling original onClickMe method
[*] Hook Done
```

You can also try to set `this.m = 1000` in example.py, then click the button, and it will print "Failed" again. 



## Task2 (optional) 

As introduced in `L5.2-Frida.pptx`, there are various usages of Frida:

- Traverse all loaded class
- Manipulate Classes 
- Hook native methods
- Hook libc functions
- ...

You can also find many code snippets of examples at https://github.com/iddoeldor/frida-snippets.

In this task, you are required to select at least 3 different usages of fFridalisted above (or in frida-snippets), implement the usages, and test with your APKs.
