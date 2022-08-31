if (Test-Path -Path .\bin\lab6.exe -PathType Leaf) {
    Remove-Item .\bin\lab6.exe
}

x86_64-w64-mingw32-g++ -I include/ -static -std=c++20 -lstdc++fs -o bin/lab6.exe src/lab6.cpp