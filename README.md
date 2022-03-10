Steps to install acc-bpf on DUT
================================
#### By deb
- On Linux server
```
  1. install python3-stdeb and other required packages. 
  2. git clone https://github.com/.../acc-bpf
  3. cd acc-bpf; ./build_deb.sh
  4. copy output deb file to DUT
```
- On DUT
```
  1. python3 and python3-bpfcc is required 
  2. dpkg -i <output deb file>
```

