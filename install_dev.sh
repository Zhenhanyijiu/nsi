#需要工具
if [ ! -d "./mPSI" ]; then
	echo "=======不存在mPSI目录========"
	echo "git clone mpsi start"
	git clone git://github.com/asu-crypto/mPSI.git
 	echo "git clone mpsi ok"
fi
#工作目录psi3
DEV_PARH="/tmp"
#创建依赖库目录
if [ ! -d "./libdev" ]; then
	echo "=======不存在libdev目录========"
	echo "create libdev"
	mkdir libdev
 	echo "dev_path:`pwd`/libdev"
else
	echo "=======存在libdev目录========"
	rm -rf ./libdev/*
fi
CURR_PATH=${PWD}
DEV_PATH=${CURR_PATH}/libdev
echo "libdev is in ${DEV_PATH}"
#
#if [ ! $1 ]; then
#  echo "IS NULL"
#  echo "dev_path:${DEV_PATH}"
#else
#  echo "NOT NULL"
#  DEV_PATH=$1
#  echo "dev_path:${DEV_PATH}"
#fi

if [ ! -d "./linbox" ]; then
	# rm -rf linbox
	echo "=============git clone linbox====="
	git clone git://github.com/linbox-team/linbox.git
fi

cd linbox
if [ -f "install_start_func.sh" ]; then
	# rm -rf linbox
	rm -rf install_start_func.sh
fi
cp -r ../install_start_func.sh .
bash install_start_func.sh --prefix=${DEV_PATH}  --enable-openblas=yes --enable-gmp=yes --enable-ntl=yes


pwd
pwd
cd ..
#这里是工作目录psi3
###编译ntl
echo "编译ntl==============>"
cd ./linbox/build/ntl-11.4.3/src/
make clean
make ./ntl.a CXXFLAGS="-fPIC -shared"
mv ./ntl.a ${DEV_PATH}/lib/libntl.a
cd -

rm -rf ./linbox/build