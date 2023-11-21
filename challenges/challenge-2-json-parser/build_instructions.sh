mkdir YAJL/build && cd YAJL/build
export AFL_USE_ASAN=1
CC=afl-cc CXX=afl-c++ cmake ..
make clean; make -j 8

export LD_LIBRARY_PATH=/AFLplusplus/security-software-lifecycle/challenges/challenge-2-json-parser/YAJL/build/yajl-2.1.1/lib/:$LD_LIBRARY_PATH
afl-cc -fsanitize=address -o json_reader json_reader.c  -lyajl \
-I /AFLplusplus/include
-I'/AFLplusplus/security-software-lifecycle/challenges/challenge-2-json-parser/YAJL/build/yajl-2.1.1/include' \
-L'/AFLplusplus/security-software-lifecycle/challenges/challenge-2-json-parser/YAJL/build/yajl-2.1.1/lib' \

afl-fuzz -i ./seeds -o ./findings -x json.dict -- ./json_reader 


