mkdir YAJL/build && cd YAJL/build
export AFL_USE_ASAN=1
CC=afl-cc CXX=afl-c++ cmake ..
make clean; make -j 8

export AFL_PRELOAD='/mnt/YAJL/build/yajl-2.1.1/lib' \
afl-cc -fsanitize=address -o json_reader json_reader.c \
    -lyajl -I'/mnt/YAJL/build/yajl-2.1.1/include' \
    -L'/mnt/YAJL/build/yajl-2.1.1/lib' \
    -I/AFLplusplus/include

afl-fuzz -i ./seeds -o ./findings -x json.dict -- ./json_reader 
