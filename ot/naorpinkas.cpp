#include "naorpinkas.h"

#include <cryptoTools/Common/Log.h>
#include <cryptoTools/Common/Timer.h>
#include <cryptoTools/Crypto/sha1.h>

#define PARALLEL
#ifdef NAOR_PINKAS
// #include <memory>
void print_error(int n)
{
    std::cout << "========error!!! error:" << n << endl;
}
namespace osuCrypto
{

    //static const  u64 minMsgPerThread(16);
    /***********************
    naor-pinkas ot protocal for Sender
    ************************/
    NaorPinkasSender::NaorPinkasSender()
    {
    }
    NaorPinkasSender::~NaorPinkasSender()
    {
        // delete this->alphaPtr;
        // delete this->curve;
    }
    int NaorPinkasSender::init(PRNG &rng, const u32 otMsgPairSize,
                               const u32 otPerMsgBitSize)
    {
        printf("========sender init==========\n");
        this->otMsgPairSize = otMsgPairSize;
        this->otPerMsgBitSize = otPerMsgBitSize;
        block seed = rng.get<block>();
        this->prng.SetSeed(seed);
        seed = this->prng.get<block>();
        EllipticCurve curve(k233, seed);
        EccNumber alpha(curve);
        alpha.randomize(this->prng);
        // cout << "[sender]我是a：" << alpha << endl;
        this->alphaPtr.resize(alpha.sizeBytes());
        alpha.toBytes(this->alphaPtr.data());
        return 0;
    }

    int NaorPinkasSender::genPublicParam(u8 **pubParamBuf, u64 *pubParamBufByteSize)
    {
        printf("========sender genPublicParam==========\n");
        block seed = this->prng.get<block>();
        EllipticCurve curve(k233, seed);
        const EccPoint g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        printf("[sender]fieldElementSize:%ld\n", fieldElementSize);
        cout << "[sender]G:" << g << endl;
        u64 byteSize = fieldElementSize * 2;
        vector<EccPoint> pC;
        pC.reserve(2);
        this->pubPCParamBuf.resize(byteSize);
        pC.emplace_back(curve);
        EccNumber alpha(curve);
        alpha.fromBytes(this->alphaPtr.data());
        pC[0] = g * alpha; // A=alpha*G
        // cout << "[sender]A=g^a:" << pC[0] << endl;
        pC[0].toBytes(this->pubPCParamBuf.data());
        EccNumber tmp(curve);
        for (u64 u = 1; u < 2; u++)
        {
            pC.emplace_back(curve);
            tmp.randomize(this->prng);
            pC[u] = g * tmp; // C=tmp*G
            // cout << "[sender]C=g^c:" << pC[u] << endl;
            pC[u].toBytes(this->pubPCParamBuf.data() + u * fieldElementSize);
        }
        *pubParamBuf = this->pubPCParamBuf.data();
        if (*pubParamBuf == nullptr)
        {
            print_error(-1);
            return -1;
        }
        *pubParamBufByteSize = byteSize;
        return 0;
    }
    int NaorPinkasSender::getEncKey(u8 *pk0Buf, const u64 pk0BufSize,
                                    vector<array<block, 2>> &encKeys)
    {
        printf("========sender getEncKey==========\n");
        block seed = this->prng.get<block>();
        EllipticCurve curve(k233, seed);
        const EccPoint g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        u64 encKeySize = this->otMsgPairSize;
        if (pk0Buf == nullptr || pk0BufSize != fieldElementSize * encKeySize)
        {
            print_error(-2);
            return -2;
        }
        encKeys.resize(encKeySize);
        // u64 pk0Num = pk0BufSize / fieldElementSize;
        EccPoint pPK0(curve), PK0a(curve), fetmp(curve);
        // Number alpha2(curve, alpha);
        std::vector<u8> hashInBuff(fieldElementSize); // 33字节
        //todo:这里的randomoracle的输出长度是否固定？？？
        SHA1 sha; // 16字节
        u8 output_tmp[20];
        // printf("===============>>before for\n");
        // EccNumber alpha2(*(this->curve), *(this->alphaPtr));
        EccNumber alpha(curve);
        alpha.fromBytes(this->alphaPtr.data());
        EccPoint C(curve);
        C.fromBytes(this->pubPCParamBuf.data() + fieldElementSize);
        for (int i = 0; i < encKeySize; i++)
        {
            //对于第i对消息，获取pPK0==k*G
            pPK0.fromBytes(pk0Buf + i * fieldElementSize);
#if 0
            if (i == 0)
            {
                cout << "[sender]pk0:" << pPK0 << endl;
                cout << "[sender]a:" << alpha << endl;
            }
#endif
            //计算a*pPK0
            PK0a = pPK0 * alpha;
#if 0
            if (i == 0)
            {
                cout << "[sender] gka=pk0*a:" << PK0a << endl;
            }
#endif
            //将点转化成压缩形式
            PK0a.toBytes(hashInBuff.data()); // PK0a=(x,y),取x
            //计算hash，text=i||hashInBuff||R做hash运算,并将结果存到messages[i][0]中
            sha.Reset();
            sha.Update((u8 *)&i, sizeof(i));
            sha.Update(hashInBuff.data(), hashInBuff.size());
            // sha.Update(R);
            //结果存到messages[i][0]中,output_tmp
            sha.Final(output_tmp);
            encKeys[i][0] = *((block *)output_tmp);
            //处理另一个Ca/PK0a
            fetmp = C * alpha - PK0a;
#if 0
            if (i == 0)
            {
                cout << "[sender]C*a-pk0*a:" << fetmp << endl;
            }
#endif
            fetmp.toBytes(hashInBuff.data());
            sha.Reset();
            sha.Update((u8 *)&i, sizeof(i));
            sha.Update(hashInBuff.data(), hashInBuff.size());
            // sha.Update(R);
            //结果存到 encKeys[i][1]
            sha.Final(output_tmp);
            encKeys[i][1] = *((block *)output_tmp);
        }
        ////
        return 0;
    }
    // int NaorPinkasSender::genOTCipher(const vector<array<block, 2>> &encKey,
    //                                   const vector<array<block, 2>> &otMessages,
    //                                   vector<array<block, 2>> &otMsgCiphers)
    // {
    //     u64 encKeySize = encKey.size();
    //     u64 otMessagesSize = otMessages.size();
    //     // u64 otMsgCiphersSize = otMsgCiphers.size();
    //     if (otMsgPairSize != encKeySize || otMsgPairSize != otMessagesSize)
    //     {
    //         print_error(-3);
    //         return -3;
    //     }
    //     otMsgCiphers.resize(otMsgPairSize);
    //     for (int i = 0; i < otMessagesSize; i++)
    //     {
    //         otMsgCiphers[i][0] = encKey[i][0] ^ otMessages[i][0];
    //         otMsgCiphers[i][1] = encKey[i][1] ^ otMessages[i][1];
    //     }
    //     ////
    //     return 0;
    // }
    /*
    naor-pinkas ot protocal for Receiver
    */
    NaorPinkasReceiver::NaorPinkasReceiver() {}
    NaorPinkasReceiver::~NaorPinkasReceiver()
    {
        // delete this->curve;
    }
    int NaorPinkasReceiver::init(PRNG &rng, const u32 otMsgPairSize,
                                 const u32 otPerMsgBitSize)
    {
        printf("========recv init==========\n");
        this->otMsgPairSize = otMsgPairSize;
        this->otPerMsgBitSize = otPerMsgBitSize;
        block seed = rng.get<block>();
        this->prng.SetSeed(seed);
        return 0;
    }
    int NaorPinkasReceiver::genPK0(u8 *pubParamBuf, const u64 pubParamBufByteSize,
                                   const BitVector &choices, u8 **pk0Buf_out, u64 *pk0BufSize)
    {
        printf("========recv genPK0==========\n");
        u64 rNum = choices.size();
        cout << "rNum:" << rNum << endl;
        cout << "otMsgPairSize:" << this->otMsgPairSize << endl;
        if (pubParamBuf == nullptr || pk0Buf_out == nullptr || rNum != otMsgPairSize)
        {
            print_error(-4);
            return -4;
        }
        block seed = this->prng.get<block>();
        EllipticCurve curve(k233, seed);
        const EccPoint g = curve.getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        cout << "[recv]G:" << g << endl;
        //恢复对方发来的A,C两个公钥点
        this->pC.resize(fieldElementSize * 2);
        memcpy(this->pC.data(), pubParamBuf, pubParamBufByteSize);
        EccPoint A(curve), C(curve);
        A.fromBytes(pubParamBuf + 0 * fieldElementSize);
        C.fromBytes(pubParamBuf + 1 * fieldElementSize);
#if 0
        cout << "[recv]A:" << A << endl;
        cout << "[recv]C:" << C << endl;
#endif
        this->sks.resize(otMsgPairSize);
        vector<EccPoint> pks_sk;
        pks_sk.reserve(otMsgPairSize);
        *pk0BufSize = fieldElementSize * otMsgPairSize;
        this->pk0sBuf.resize(*pk0BufSize);
        *pk0Buf_out = this->pk0sBuf.data();
        // EccBrick bg(g);      //基点G
        EccPoint pk0(curve); //Ar
        // EccPoint pPK0(*(this->curve)); //Ar
        u64 offset = 0;
        for (int i = 0; i < otMsgPairSize; i++)
        {
            EccNumber tmp_sk(curve);
            tmp_sk.randomize(prng);
// this->sks.emplace_back(*(this->curve));
// k1,k2,...,kk
#if 0
            if (i == 0)
            {
                cout << "[recv]k1:" << tmp_sk << endl;
            }
#endif

            this->sks[i].resize(tmp_sk.sizeBytes());
            tmp_sk.toBytes(this->sks[i].data());
            pks_sk.emplace_back(curve); //每次初始化一个ECCPoint
            pks_sk[i] = g * tmp_sk;     //生成对应的公钥g^k
            //根据选择0 or 1，计算A0
            u8 r = choices[i];
            if (r != 0)
            {
                pk0 = C - pks_sk[i];
            }
            else
            {
                pk0 = pks_sk[i];
            }
            pk0.toBytes(this->pk0sBuf.data() + offset);
#if 0
            if (i == 0)
            {
                cout << "[recv]pk0:" << pk0 << endl;
            }
#endif

            offset += fieldElementSize;
        }
        return 0;
    }
    int NaorPinkasReceiver::getDecKey(vector<block> &decKey)
    {
        printf("========recv getDecKey==========\n");
        decKey.resize(this->otMsgPairSize);
        block seed = this->prng.get<block>();
        EllipticCurve curve(k233, seed);
        const EccPoint g = curve.getGenerator();
        EccPoint PK0(curve);
        EccPoint &gka = PK0;
        u64 fieldElementSize = g.sizeBytes();
// cout << "fieldElementSize:" << fieldElementSize << endl;
#if 0
        cout << "[recv]2 G:" << g << endl;
#endif
        SHA1 sha; //otPerMsgBitSize
        vector<u8> buff(fieldElementSize);
        EccPoint A(curve), C(curve);
        A.fromBytes(this->pC.data() + 0 * fieldElementSize);
#if 0
        cout << "[recv]A:" << A << endl;
#endif
        u8 output_tmp[20];
        for (int i = 0; i < this->otMsgPairSize; i++)
        {
            EccNumber tmp_sk(curve);
            tmp_sk.fromBytes(this->sks[i].data());
            // now compute g ^(a * k) = (g^a)^k=A^k
            gka = A * tmp_sk; //计算恢复消息的
            gka.toBytes(buff.data());
#if 0
            if (i == 0)
            {
                cout << "[recv]k1:" << tmp_sk << endl;
                cout << "[recv]gka=A*k1:" << gka << endl;
            }
#endif

            //计算hash，text=i||gka||R作为hash输入
            sha.Reset();
            sha.Update((u8 *)&i, sizeof(i));
            sha.Update(buff.data(), buff.size());
            // sha.Update(R);
            //将密钥存到messges中
            sha.Final(output_tmp);
            // sha.Final(decKey[i]);
            decKey[i] = *((block *)output_tmp);
        }
        return 0;
    }
    // int NaorPinkasReceiver::genOTRecover(const vector<block> &decKey, const BitVector &choices,
    //                                      const vector<array<block, 2>> &otMsgCiphers,
    //                                      vector<block> &otMsgRecover)
    // {
    //     if (decKey.size() != otMsgPairSize || choices.size() != otMsgPairSize ||
    //         otMsgCiphers.size() != otMsgPairSize)
    //     {
    //         print_error(-6);
    //         return -6;
    //     }
    //     otMsgRecover.resize(otMsgPairSize);
    //     for (int i = 0; i < otMsgPairSize; i++)
    //     {
    //         u8 r = choices[i];
    //         otMsgRecover[i] = otMsgCiphers[i][r] ^ decKey[i];
    //     }
    //     return 0;
    // }
}

#endif

////test////
#ifdef NP99_TEST
namespace oc = osuCrypto;
// #include <vector>
#include "naorpinkas.h"
// using namespace std;
using namespace oc;
void check_np99(vector<array<block, 2>> &enckey, vector<block> &deckey, BitVector &rChoices)
{
    for (int i = 0; i < rChoices.size(); i++)
    {
        int r = rChoices[i];
        int ret = memcmp((char *)(&(deckey[i])), (char *)(&(enckey[i][r])), 16);
        if (ret != 0)
        {
            printf("===>>error,i:%d\n", i);
            return;
        }
    }
}

int main(int argc, char **argv)
{
#ifdef ECC_TEST
    int nn = atoi(argv[1]);
    PRNG rng1(toBlock(0x666666));
    block seed = rng1.get<block>();
    block seed1 = rng1.get<block>();
    EllipticCurve curve1(k233, seed1);
    EllipticCurve curve(k233, seed);
    const EccPoint g = curve.getGenerator();
    //alpha也可以定义为长度为1的vector，此时就不需要指针了
    // this->alphaPtr = new EccNumber(*(this->curve), this->prng); //*(this->curve)
    EccNumber alphaPtr(curve); //*(this->curve)
    alphaPtr.randomize(rng1);
    EccPoint pk(curve1), pk1(curve1), pk2(curve);
    pk = g * (alphaPtr);
    cout << "===>>pk:" << pk << endl;

    EccNumber a1(curve);
    EccNumber a2(curve);
    a1.randomize(rng1);
    cout << "===>>a1:" << a1 << endl;
    a2.randomize(rng1);
    cout << "===>>a2:" << a2 << endl;
    pk1 = pk * a1;
    pk2 = pk * a2;
    cout << "===>>pk1:" << pk1 << endl;
    cout << "===>>pk2:" << pk2 << endl;
    EccPoint pk3(curve1), pk4(curve);
    pk3 = pk1 * a2;
    pk4 = pk2 * a1;
    cout << "===>>pk3:" << pk3 << endl;
    cout << "===>>pk4:" << pk4 << endl;
    for (int i = 0; i < nn; i++)
    {

        alphaPtr.randomize(rng1);
        pk2 = pk * alphaPtr;
        cout << "pk :==" << pk2 << endl;
        cout << "alphaPtr :==" << alphaPtr << endl;
        cout << ">>>>len:" << alphaPtr.sizeBytes() << endl;
        u8 buf[64];
        pk2.toBytes(buf);
        pk1.fromBytes(buf);
        cout << "pk1:==" << pk1 << endl;
        pk = pk2;
    }
    // delete alphaPtr;
    // delete curve1;
    // delete curve;
    return 0;

#endif
    if (argc != 2)
    {
        printf("========error!!! argc!=2\n");
        return -1;
    }
    int flag = 0;
    //生成需要处理的消息对
    int pairs = atoi(argv[1]);
    printf("===>>input pairs:%d\n", pairs);
    int otMsgPairsSize = pairs;
    // vector<array<oc::block, 2>> otMsg(otMsgPairsSize);
    // genOTMsg(otMsg);
    // printOTMsg(otMsg);
    u8 r[8] = {0x77, 0xaa, 0xcb, 0x2b, 0xfd, 0xaf, 0x96, 0xea};
    PRNG rng(toBlock(0x666666));
    vector<block> dest_block;
    dest_block.resize(pairs / 128 + 1);
    rng.get<block>(dest_block.data(), pairs / 128 + 1);
    BitVector rChoices((u8 *)dest_block.data(), otMsgPairsSize);
    cout << "===rChoices:" << rChoices << ",size:" << rChoices.size() << endl;
    //初始化一个np-ot-sender
    NaorPinkasSender npSender;
    npSender.init(rng, otMsgPairsSize, 128);
    u8 *buf_AC = NULL;
    uint64_t bufSize = 0;
    cout << "=====before genpubparam...\n";
    //生成公共参数AC，并将AC发送给receiver
    flag = npSender.genPublicParam(&buf_AC, &bufSize);
    cout << "1===>>flag:" << flag << endl;
    cout << "=====after  genpubparam...\n";
    //初始化一个np-ot-receiver
    NaorPinkasReceiver npReceiver; //(oc::toBlock(0x332211), otMsgPairsSize);
    npReceiver.init(rng, otMsgPairsSize);
    u8 *pk0buf = nullptr;
    u64 pk0bufSize = 0;
    //传入公共参数AC，并生成pk0发送给sender方
    flag = npReceiver.genPK0(buf_AC, bufSize, rChoices, &pk0buf, &pk0bufSize);
    for (int i = 0; i < 100; i++)
    {
        printf("%x", pk0buf[i]);
    }
    printf(">>>>>>>所有psk0s pk0bufSize:%ld\n", pk0bufSize);
    cout << "2===>>flag:" << flag << endl;
    vector<array<block, 2>> enckey;
    // u8 pk0bufNew[pk0bufSize];
    // memcpy(pk0bufNew, pk0buf, pk0bufSize);
    // printf("====pk0bufNew::::\n");
    for (int i = 0; i < 100; i++)
    {
        printf("%x", pk0buf[i]);
    }
    flag = npSender.getEncKey(pk0buf, pk0bufSize, enckey);
    cout << "3===>>flag:" << flag << endl;
    // for (int i = 0; i < enckey.size(); i++)
    for (int i = 0; i < 2; i++)
    {
        cout << "i:" << i << " " << enckey[i][0] << endl;
        cout << "i:" << i << " " << enckey[i][1] << endl;
    }
    // vector<array<block, 2>> otMsgCipher;
    //对每一对消息进行加密，并发送给receiver
    // flag = npSender.genOTCipher(enckey, otMsg, otMsgCipher);
    cout << "4===>>flag:" << flag << endl;
    //获取解密密钥
    vector<block> deckey;
    flag = npReceiver.getDecKey(deckey);
    cout << "5===>>flag:" << flag << endl;
    // for (int i = 0; i < deckey.size(); i++)
    for (int i = 0; i < 2; i++)
    {
        cout << "i:" << i << " " << deckey[i] << endl;
    }
    printf("===check np99...\n");
    check_np99(enckey, deckey, rChoices);
    // vector<oc::block> otMsgRecover;
    // flag = npReceiver.genOTRecover(deckey, rChoices, otMsgCipher, otMsgRecover);
    // cout << "6===>>flag:" << flag << endl;
    // cout << "===>>recover:" << otMsgRecover[0] << endl;
    // check_recover(otMsg, rChoices, otMsgRecover);
    return 0;
}
#endif