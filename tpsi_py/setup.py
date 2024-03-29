# cython:language_level=3
# from distutils.core import setup
from Cython.Build import cythonize
from distutils.core import setup, Extension
from Cython.Distutils import build_ext
import os


# 获取源文件列表方法
def get_source_files(src_dir, str_fix=".cpp"):
    datanames = os.listdir(src_dir)
    # print("===ls:", datanames)
    flist = []
    for dataname in datanames:
        if os.path.splitext(dataname)[1] == str_fix:  # 目录下包含.cpp 的文件
            # print(dataname)
            flist.append(src_dir + "/" + dataname)
    return flist


# 编译静态库libmiracl
def compile_miracl_xxhash_boost():
    # miracl_path = THIRD_INCLUDE + "/miracl/miracl/source/"
    # cmd = 'cd ' + miracl_path + " && g++ -g -fPIC -shared -c -m64 -O3 ./*.c -I../include " + \
    #       " && ar rc libmiracl.a ./*.o" + " && rm -rf ./*.o" + " &&cd -"
    os.system("bash setup_prepare.sh")


# cython编译
BIN_PATH = "../tpsi_bin_bak"
BIN_PATH = "../src"


def start_setup():
    # 用源文件编译,获取源文件列表
    source_files = []
    source_files += ["tpsi.pyx"]
    # cryptotools
    source_files += get_source_files("../mPSI/cryptoTools/Network")
    source_files += get_source_files("../mPSI/cryptoTools/Crypto")
    source_files += get_source_files("../mPSI/cryptoTools/Common")
    # libote
    source_files += get_source_files("../mPSI/libOTe/TwoChooseOne")
    source_files += get_source_files("../mPSI/libOTe/NChooseOne")
    source_files += get_source_files("../mPSI/libOTe/Base")
    source_files += get_source_files("../mPSI/libOTe/Tools")
    # liboprf
    source_files += get_source_files("../mPSI/libOPRF/OPPRF")
    source_files += get_source_files("../mPSI/libOPRF/Hashing")
    # libPaXoS
    source_files += [
        "../mPSI/libPaXoS/ObliviousDictionary.cpp",
        "../mPSI/libPaXoS/gf2e_mat_solve.cpp",
    ]
    # tpsi_src
    source_files += get_source_files(BIN_PATH)
    # mPSI
    tmp_cpp = get_source_files('../mPSI/frontend')
    # if "../mPSI/frontend/main.cpp" in tmp_cpp:
    frontend_files = [x for x in tmp_cpp if x != "../mPSI/frontend/main.cpp"]
    print('======mpsi frontend files:', frontend_files)
    source_files = source_files+frontend_files
    LINBOX_DEV_PATH = "../libdev"
    # 获取头文件路径路径，-I
    #   '../thirdparty/linux/ntl/include',
    include_dirs = [
        BIN_PATH,
        '../mPSI/frontend',
        "../mPSI/cryptoTools",
        "../mPSI/thirdparty/linux/boost/includes",
        "../mPSI/libOPRF",
        "../mPSI/libOTe",
        "../mPSI/libPaXoS",
        "../mPSI/thirdparty/linux/miracl",
        LINBOX_DEV_PATH + "/include",
    ]

    # 宏定义
    define_macros = [("NDEBUG", None), ("NO_INTEL_ASM_SHA1", 1)]
    # 其他编译条件，-std=gnu++11,-std=c++11
    extra_compile_args = [
        "-g",
        "-std=c++11",
        "-Wall",
        "-O2",
        "-pthread",
        "-msse3",
        "-msse2",
        "-msse4.1",
        "-maes",
        "-mpclmul",
    ]

    # 链接omp
    extra_link_args = ["-llinbox", "-lopenblas", "-lgivaro", "-lgmp"]
    # extra_link_args = ['-llinbox', '-lopenblas',
    #                    '-lgivaro',  '-lgomp','-lgmpxx']
    # ../libPaXoS/xxHash/libxxhash.a
    # 依赖库路径，-L
    # '../thirdparty/linux/ntl/src',
    library_dirs = [
        "../mPSI/thirdparty/linux/boost/stage/lib",
        "../mPSI/thirdparty/linux/miracl/miracl/source",
        "../mPSI/libPaXoS/xxHash",
        LINBOX_DEV_PATH + "/lib",
    ]
    # 库名，-l
    libraries = ["xxhash", "miracl", "ntl", "boost_system"]
    ext1 = Extension(
        "tpsi",
        sources=source_files,
        include_dirs=include_dirs,
        define_macros=define_macros,
        library_dirs=library_dirs,
        libraries=libraries,
        extra_compile_args=extra_compile_args,
        extra_link_args=extra_link_args,
        language="c++",
    )
    setup(
        cmdclass={"build_ext": build_ext},
        ext_modules=cythonize(ext1),
    )


# python3 setup.py build_ext --inplace
if __name__ == "__main__":
    print("======== 首先编译boost,miracl,xxhash")
    compile_miracl_xxhash_boost()
    print("======== 编译 tpsi cython 接口开始 ========")
    start_setup()
    print("======== 删除编译中产生的临时文件 ========")
    os.system("rm -rf build/ tpsi.cpp")
