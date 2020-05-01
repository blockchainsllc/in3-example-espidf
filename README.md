# Embedded Devices

## Hardware Requirements

### Memory 


| Memory type                 | Free size KB |
| ------------------------ | -------- |
| **Dynamic memory(DRAM)** | 30 - 50   |
| **Flash Memory**         | 150 - 200   |


### Networking

In3 client needs to have a reliable internet connection to work properly, so your hardware must support any network interface or module that could give you access to it. i.e  Bluetooth, Wifi, ethernet, etc.
        
## Incubed with ESP-IDF

### Use case example: Airbnb Property access

A smart door lock that grants access to a rented flat is installed on the property. It is able to connect to the Internet to check if renting is allowed and that the current user is authorized to open the lock.

The computational power of the control unit is restricted to the control of the lock. And it is also needed to maintain a permanent Internet connection.

You want to enable this in your application as an example of how in3 can help you, we will guide through the steps of doing it, from the very basics and the resources you will need 

**Hardware requirements**

![hardware_requirements](./embedded_esp.png)

* [ESP32-DevKitC V4](https://docs.espressif.com/projects/esp-idf/en/latest/hw-reference/get-started-devkitc.html) or similar dev board
* Android phone
* Laptop MAC, Linux, Windows
* USB Cable 

**Software requirements** 

* [In3](https://github.com/slockit/in3-c) C client
* Esp-idf toolchain and sdk, (please follow this [guide](https://docs.espressif.com/projects/esp-idf/en/stable/get-started/)) and be sure on the cloning step to use `release/v4.0` branch

`git clone -b release/v4.0 --recursive https://github.com/espressif/esp-idf.git` 

* [Android Studio](https://developer.android.com/studio)
* [Silab](https://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers) USB drivers 
* Solidity smart contract: we will control access to properties using a public smart contract, for this example, we will use the following template:


```
pragma solidity ^0.5.1;

contract Access {
    uint8 access;
    constructor() public  {
        access = 0;
    }
    
    function hasAccess() public view returns(uint8) {
        return access;
    }
    
    function setAccess(uint8 accessUpdate) public{
        access = accessUpdate;
    }
}
```

**How it works**

![sequence diagram](./embedded_diagram.png)

In3 will support a wide range of microcontrollers, in this guide we will use well-known esp32 with freertos framework, and an example android app to interact with it via Wifi connection. 

**Instalation instructions**

1. Clone the repo

`git clone --recursive https://github.com/slockit/in3-example-espidf`

2. Deploy the contract with your favorite tool (truffle, etc) or use our previously deployed contract on goerli

3. Configure your SSID, password and contract address by running `make menuconfig`, then go to `Component config` / `IN3`. `Save` and `Exit`. A file named `sdkconfig` must have been created with your specific config. 

4. Build the code

`idf.py build`

5. Connect the usb cable to flash and monitor the serial output from the application. 

`idf.py flash && idf.py monitor`

after the build finishes and the serial monitor is running you will see the configuration and init logs.

6. Configure the IP address of the example, to work with. Take a look at the inital output of the serial output of the `idf.py monitor` command, you will see the IP address, as follows:

```
I (2647) tcpip_adapter: sta ip: 192.168.178.64, mask: 255.255.255.0, gw: 192.168.178.1
I (2647) IN3: got ip:192.168.178.64
```
take note if your ip address which will be used in the Android application example. 

7. Clone the android repository, compile the android application and install the in3 demo application in your phone. 

`git clone https://github.com/slockit/in3-android-example`

8. Modify the android source changing IP address variable inside kotlin source file `MainActivity.kt`, with the IP address found on step 6.

`(L:20) private const val ipaddress = "http://192.168.xx.xx"`

9. If you want to test directly without using Android you can also do it with the following HTTP cURL requests:

* `curl -X GET http://slock.local/api/access`

* `curl -X GET http://slock.local/api/retrieve`

we need 2 requests as the verification process needs to be executed in asynchronous manner, first one will trigger the execution and the result could be retrieved with the second one 




