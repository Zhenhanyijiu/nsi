#该脚本编译出frontend.exe可执行文件
#当前目录有lib依赖库libcryptoTools.a、liblibOPRF.a、liblibOTe.a、liblibPaXoS.a
#否则先编译出上述依赖库
#-lboost_system
# -fPIC -shared
#g++ -O3 -DNDEBUG -O2 -g -O0 -ffunction-sections -Wall -Wfatal-errors \
#-maes -msse2 -msse4.1 -mpclmul -std=gnu++14 -pthread \
#-I ./cryptoTools \
#-I ./thirdparty/linux/boost/includes \
#-I ./libOPRF \
#-I ./libOTe \
#-I ./libPaXoS \
#-I ./thirdparty/linux/miracl/ \
#-I ./thirdparty/linux/ntl/include/ \
#-I ./frontend \
#-L ./thirdparty/linux/boost/stage/lib \
#-L lib \
#-L thirdparty/linux/miracl/miracl/source \
#-L thirdparty/linux/ntl/src/ \
#frontend/CLP.cpp \
#frontend/OtBinMain.cpp \
#frontend/OtBinMain.v2.cpp \
#frontend/bitPosition.cpp \
#frontend/miraclTest.cpp \
#frontend/util.cpp \
#./lib/liblibPaXoS.a \
#./lib/liblibOTe.a \
#./lib/liblibOPRF.a \
#-lcryptoTools -lmiracl -lntl -lboost_system \
#./frontend/main.cpp -o frontend.exe \

# -lcryptoTools -llibOPRF -llibOTe -lmiracl -lntl \
#nasm -f elf64 ../cryptoTools/Crypto/asm/sha_lnx.S -o ../cryptoTools/Crypto/asm/sha_lnx.S.o
#../cryptoTools/Crypto/asm/sha_lnx.S.o \
# -DNO_INTEL_ASM_SHA1=1 -DTEST_PSI3 \
#-fPIC -shared
#./b2 stage --with-system --with-thread link=static -mt -fPIC -shared
#-lboost_system 
#-I ../thirdparty/linux/ntl/include/ \
#-L ../thirdparty/linux/ntl/src/ \
#编译ntl

CURRENT_PATH="$PWD"
echo ${CURRENT_PATH}
if [ ! -f "../mPSI/thirdparty/linux/ntl-11.4.3.tar.gz" ];then
    cd ../mPSI/thirdparty/linux/
    wget https://libntl.org/ntl-11.4.3.tar.gz
    cd -
fi
# echo "编译xxhash==============>"
# cd ../mPSI/libPaXoS/xxHash 
# g++ -g -fPIC -shared -c ./*.c
# ar rc libxxhash.a ./*.o
# cd -

if [ ! -f "../mPSI/thirdparty/linux/ntl-11.4.3/src/libntl.a" ];then
    cd ../mPSI/thirdparty/linux/
    tar zxvf ntl-11.4.3.tar.gz
    cd ntl-11.4.3/src/
    #wsl用这里
    # ./configure PREFIX=`pwd` GMP_PREFIX="${CURRENT_PATH}/../libdev"
    make clean
    #docker用这里
    ./configure PREFIX=`pwd`
    make -j4
    make install
    cp -r lib/libntl.a .
    # make clean
    # make -j4 ./ntl.a 
    # mv ./ntl.a ./libntl.a
    # bash ntl.get
    # cd - & cd ../../psi3_bin/
    cd ${CURRENT_PATH}
fi

echo "========pwds start==========="
pwd
pwd
echo "========pwds end=============="

if [ -f "tpsi" ];then
    rm -rf tpsi
fi
#将第三方库的main文件去掉
if [ -f "../mPSI/frontend/main.cpp" ];then
    if [ ! -f "../mPSI/frontend/main.cpp-bak" ];then
        # rm -rf ../mPSI/frontend/main.cpp-bak
        mv ../mPSI/frontend/main.cpp ../mPSI/frontend/main.cpp-bak
    else
        rm -rf ../mPSI/frontend/main.cpp
    fi
fi
# -DTPSI_TEST -DECC_TEST -DIKNP_TEST
g++ -O3 -DNDEBUG -O2 -g -O0 -ffunction-sections -Wall -Wfatal-errors \
-maes -msse2 -msse3 -msse4.1 -mpclmul -std=c++11 -pthread \
-DNO_INTEL_ASM_SHA1=1 -DIKNP_TEST \
-I ../mPSI \
-I ../src \
-I ../mPSI/frontend \
-I ../mPSI/cryptoTools \
-I ../mPSI/thirdparty/linux/boost/includes \
-I ../libdev/include \
-I ../mPSI/libOPRF \
-I ../mPSI/libOTe \
-I ../mPSI/libPaXoS \
-I ../mPSI/thirdparty/linux/miracl/ \
-L ../mPSI/thirdparty/linux/boost/stage/lib \
-L ../mPSI/thirdparty/linux/miracl/miracl/source \
-L ../libdev/lib \
../mPSI/cryptoTools/Network/*.cpp \
../mPSI/cryptoTools/Crypto/*.cpp \
../mPSI/cryptoTools/Common/*.cpp \
../mPSI/libOTe/TwoChooseOne/*.cpp \
../mPSI/libOTe/NChooseOne/*.cpp \
../mPSI/libOTe/Base/*.cpp \
../mPSI/libOTe/Tools/*.cpp \
../mPSI/libOPRF/OPPRF/*.cpp \
../mPSI/libOPRF/Hashing/*.cpp \
../mPSI/libPaXoS/ObliviousDictionary.cpp \
../mPSI/libPaXoS/gf2e_mat_solve.cpp \
../src/*.cpp \
../mPSI/frontend/*.cpp \
../mPSI/libPaXoS/xxHash/libxxhash.a \
../libdev/lib/liblinbox.a \
../libdev/lib/libgivaro.a \
../libdev/lib/libgmpxx.a \
../libdev/lib/libgmp.a \
../libdev/lib/libopenblas.a \
../mPSI/thirdparty/linux/ntl-11.4.3/src/libntl.a \
-lmiracl -lboost_system \
-o tpsi
# ../thirdparty/linux/ntl/src/libntl.a \
# -o libpsi3.so
#-llinbox
# -lboost_system 
# -lopenblas  -lgmp -lgomp \
#-I ../thirdparty/linux/linbox/build/fflas-ffpack \
# -I ../thirdparty/linux/linbox \
# -I ../thirdparty/linux/linbox/build/fflas-ffpack \
#-llinbox -lgivaro -lopenblas -lgmp \
# /tmp/lib/liblinbox.a \
# /tmp/lib/libgivaro.a \
# /tmp/lib/libgmpxx.a \
# /tmp/lib/libopenblas.a \
# /tmp/lib/libgmp.a \
#-lgomp 
#../libdev/lib/libgmp.a \ 