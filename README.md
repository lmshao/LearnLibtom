# Learn Libtom
该工程可以在MacOS or Linux平台上编译运行，唯一区别在于链接的动态库不同。`libs/mac`目录对应MacOS，`libs/linux`目录对应64位Linux。   
## 编译说明

- 使用Makefile直接执行make命令，该Makefile可以在MacOS or Linux上运行。
- 使用CLion打开CMakeLists.txt，默认是基于MacOS，若使用Linux，需要把CMakeLists.txt文件中`LINK_DIRECTORIES(libs/mac)`更改为`LINK_DIRECTORIES(libs/linux)` 
