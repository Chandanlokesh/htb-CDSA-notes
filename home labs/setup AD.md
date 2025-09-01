
[complete video](https://www.youtube.com/watch?v=GsmJowwIh8Q&list=PLAdEnQWAAbfXMY2D4HVZOe-ChfTKmaJfQ)

## installation

- **installing VMware Pro**
- [install vmware](https://knowledge.broadcom.com/external/article?articleNumber=368667)


- **installing windows server**
- [install windows iso](https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022)

---

## setting up vmware

- check use vmware workstation for personal use
- create a new virtual machine
- next -> i will install the os later -> select windows server 2022 -> name the server ->give a size
- right click on the machine and go to settings
	- CD/DVD -> use ISO image and select the iso image -> ok
- start the vm (press the key quickly)

---

## Setting up the win server

- opens a window installation screen press next
- install know
- select windows server 2022 standard evaluation (Desktop experience x64)
- accept 
- custom : install microsoft server os only 
- select the disk and press next

admin account setting
- password
- fish 

`systeminfo` or search winver in search bar to see the os installed version

---

## installing active directory

- we can see the server manage once we install
-  right up -> manage -> add roles and features
- next -> role based installation -> next -> select active directory domain services (window will popup press add feature ) we can select other tools like (remote access, hyper v, DNS, group manage policy management ) -> next -> next ... -> install
- promote this server to a doman controler -> add a new forest -> domain name -> `.local` -> next -> 2016 -> password to the domain -> next ... ->install
- 