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
        delete this->alphaPtr;
        delete this->curve;
    }
    int NaorPinkasSender::init(PRNG &rng, const u32 otMsgPairSize,
                               const u32 otPerMsgBitSize)
    {
        this->otMsgPairSize = otMsgPairSize;
        this->otPerMsgBitSize = otPerMsgBitSize;
        // cout << "====otMsgPairSize  :" << this->otMsgPairSize << endl;
        // cout << "====otPerMsgBitSize:" << this->otPerMsgBitSize << endl;
        this->numThreads = 1, this->nSndVals = 2;
        block seed = rng.get<block>();
        this->prng.SetSeed(seed);
        // Ecc2mParams params = k233;
        this->curve = new EllipticCurve(k233, seed);
        //alpha也可以定义为长度为1的vector，此时就不需要指针了
        // this->alphaPtr = new EccNumber(*(this->curve), this->prng); //*(this->curve)
        this->alphaPtr = new EccNumber(*(this->curve)); //*(this->curve)
        this->alphaPtr->randomize(rng);
        this->R = this->prng.get<block>();
        this->pC.reserve(nSndVals);
        return 0;
    }

    int NaorPinkasSender::genPublicParam(u8 **pubParamBuf, u64 *pubParamBufByteSize)
    {
        const EccPoint g = this->curve->getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        printf("===>>npsender fieldElementSize:%ld\n", fieldElementSize);
        u64 byteSize = fieldElementSize * this->nSndVals;
        pubPCParamBuf.resize(byteSize);
        this->pC.emplace_back(*(this->curve));
        this->pC[0] = g * (*this->alphaPtr); // A=alpha*G
        this->pC[0].toBytes(pubPCParamBuf.data());
        EccNumber tmp(*(this->curve));
        for (u64 u = 1; u < this->nSndVals; u++)
        {
            this->pC.emplace_back(*(this->curve));
            tmp.randomize(this->prng);
            this->pC[u] = g * tmp; // C=tmp*G
            this->pC[u].toBytes(pubPCParamBuf.data() + u * fieldElementSize);
        }
        cout << "sender >>>>>pc[0]:" << this->pC[0] << endl;
        cout << "sender >>>>>pc[1]:" << this->pC[1] << endl;
        *pubParamBuf = pubPCParamBuf.data();
        if (*pubParamBuf == nullptr)
        {
            print_error(-1);
            return -1;
        }
        *pubParamBufByteSize = byteSize;
        // vector<u8> sendBuff(nSndVals * fieldElementSize);
        // Number alpha2(curve, *alphaPtr);
        // std::cout << "alphaPtr:" << *alphaPtr << endl;
        // std::cout << "alpha2  :" << alpha2 << endl;
        return 0;
    }
    int NaorPinkasSender::getEncKey(u8 *pk0Buf, const u64 pk0BufSize,
                                    vector<array<block, 2>> &encKeys)
    {
        const EccPoint g = this->curve->getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        printf("===>>npsender get G,fieldElementSize：%ld\n", fieldElementSize);
        // u64 encKeySize = encKeys.size();
        u64 encKeySize = this->otMsgPairSize;
        if (pk0Buf == nullptr || pk0BufSize != fieldElementSize * encKeySize)
        {
            print_error(-2);
            return -2;
        }
        encKeys.resize(encKeySize);
        // u64 pk0Num = pk0BufSize / fieldElementSize;
        EccPoint pPK0(*(this->curve)), PK0a(*(this->curve)), fetmp(*(this->curve));
        // Number alpha2(curve, alpha);
        std::vector<u8> hashInBuff(fieldElementSize); // 33字节
        //todo:这里的randomoracle的输出长度是否固定？？？
        SHA1 sha; // 16字节
        u8 output_tmp[20];
        // printf("===============>>before for\n");
        EccNumber alpha2(*(this->curve), *(this->alphaPtr));
        for (int i = 0; i < encKeySize; i++)
        {
            //对于第i对消息，获取pPK0==k*G
            pPK0.fromBytes(pk0Buf + i * fieldElementSize);
            // for (int j = 0; j < 31; j++)
            // {
            //     printf("=====>>>%x", pk0Buf[j]);
            // }
            // printf("----------0\n");
            // cout << "====alpha:" << *(this->alphaPtr) << endl;
            cout << "===>>sender pPK0:" << pPK0 << endl;
            //计算a*pPK0
            // PK0a = pPK0 * (*(this->alphaPtr));
            PK0a = pPK0 * alpha2;
            // printf("----------1\n");
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
            fetmp = this->pC[1] * (*(this->alphaPtr)) - PK0a;
            fetmp.toBytes(hashInBuff.data());
            sha.Reset();
            sha.Update((u8 *)&i, sizeof(i));
            sha.Update(hashInBuff.data(), hashInBuff.size());
            // sha.Update(R);
            //结果存到 encKeys[i][1]
            sha.Final(output_tmp);
            encKeys[i][1] = *((block *)output_tmp);
            printf("===>>cyc i:%d### ", i);
        }
        ////
        return 0;
    }
    int NaorPinkasSender::genOTCipher(const vector<array<block, 2>> &encKey,
                                      const vector<array<block, 2>> &otMessages,
                                      vector<array<block, 2>> &otMsgCiphers)
    {
        u64 encKeySize = encKey.size();
        u64 otMessagesSize = otMessages.size();
        // u64 otMsgCiphersSize = otMsgCiphers.size();
        if (otMsgPairSize != encKeySize || otMsgPairSize != otMessagesSize)
        {
            print_error(-3);
            return -3;
        }
        otMsgCiphers.resize(otMsgPairSize);
        for (int i = 0; i < otMessagesSize; i++)
        {
            otMsgCiphers[i][0] = encKey[i][0] ^ otMessages[i][0];
            otMsgCiphers[i][1] = encKey[i][1] ^ otMessages[i][1];
        }
        ////
        return 0;
    }
    /*
    naor-pinkas ot protocal for Receiver
    */
    NaorPinkasReceiver::NaorPinkasReceiver() {}
    NaorPinkasReceiver::~NaorPinkasReceiver()
    {
        delete this->curve;
    }
    int NaorPinkasReceiver::init(PRNG &rng, const u32 otMsgPairSize,
                                 const u32 otPerMsgBitSize)
    {
        this->otMsgPairSize = otMsgPairSize;
        this->otPerMsgBitSize = otPerMsgBitSize;
        this->numThreads = 1;
        this->nSndVals = 2;
        block seed = rng.get<block>();
        this->prng.SetSeed(seed);
        // block seed = rng.get<block>();
        // this->prng.SetSeed(seed);
        // Ecc2mParams params = k233;
        this->curve = new EllipticCurve(k233, seed);

        this->pC.reserve(this->nSndVals);
        return 0;
    }
    int NaorPinkasReceiver::genPK0(u8 *pubParamBuf, const u64 pubParamBufByteSize,
                                   const BitVector &choices, u8 **pk0Buf_out, u64 *pk0BufSize)
    {
        u64 rNum = choices.size();
        cout << "rNum:" << rNum << endl;
        cout << "otMsgPairSize:" << this->otMsgPairSize << endl;
        if (pubParamBuf == nullptr || pk0Buf_out == nullptr || rNum != otMsgPairSize)
        {
            print_error(-4);
            return -4;
        }
        const EccPoint g = this->curve->getGenerator();
        u64 fieldElementSize = g.sizeBytes();
        //恢复对方发来的A,C两个公钥点
        for (auto u = 0; u < this->nSndVals; u++)
        {
            this->pC.emplace_back(*(this->curve));
            this->pC[u].fromBytes(pubParamBuf + u * fieldElementSize);
        }
        cout << "receiver >>>>>pc[0]:" << this->pC[0] << endl;
        cout << "receiver >>>>>pc[1]:" << this->pC[1] << endl;
        this->sks.reserve(otMsgPairSize);
        vector<EccPoint> pks_sk;
        pks_sk.reserve(otMsgPairSize);
        *pk0BufSize = fieldElementSize * otMsgPairSize;
        this->pk0sBuf.resize(*pk0BufSize);
        *pk0Buf_out = this->pk0sBuf.data();
        EccBrick bg(g);               //基点G
        EccPoint pk0(*(this->curve)); //Ar
        // EccPoint pPK0(*(this->curve)); //Ar
        u64 offset = 0;
        for (int i = 0; i < otMsgPairSize; i++)
        {
            this->sks.emplace_back(*(this->curve));
            // k1,k2,...,kk
            this->sks[i].randomize(prng);
            pks_sk.emplace_back(*(this->curve)); //每次初始化一个ECCPoint
            pks_sk[i] = bg * this->sks[i];       //生成对应的公钥g^k
            //根据选择0 or 1，计算A0
            u8 r = choices[i];
            if (r != 0)
            {
                pk0 = this->pC[1] - pks_sk[i];
            }
            else
            {
                pk0 = pks_sk[i];
            }
            pk0.toBytes(this->pk0sBuf.data() + offset);
            if (i == 0)
            {
                cout << ">>>>>>>>>recv pk0:" << pk0 << endl;
                // pPK0.fromBytes(this->pk0sBuf.data());
                // cout << "\n>>>>>>>>>pPK0:" << pPK0 << endl;
            }
            offset += fieldElementSize;
        }
        return 0;
    }
    int NaorPinkasReceiver::getDecKey(vector<block> &decKey)
    {
        // if (otMsgPairSize != decKey.size())
        // {
        //     print_error(-5);
        //     return -5;
        // }
        decKey.resize(this->otMsgPairSize);
        // resuse this space, not the data of PK0...
        EccPoint PK0(*(this->curve));
        EccPoint &gka = PK0;
        u64 fieldElementSize = PK0.sizeBytes();
        cout << "fieldElementSize:" << fieldElementSize << endl;
        SHA1 sha; //otPerMsgBitSize
        vector<u8> buff(fieldElementSize);
        EccBrick ga(pC[0]); // bc==A==g^a
        u8 output_tmp[20];
        for (int i = 0; i < this->otMsgPairSize; i++)
        {
            // now compute g ^(a * k) = (g^a)^k=A^k
            gka = ga * this->sks[i]; //计算恢复消息的
            gka.toBytes(buff.data());
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
    int NaorPinkasReceiver::genOTRecover(const vector<block> &decKey, const BitVector &choices,
                                         const vector<array<block, 2>> &otMsgCiphers,
                                         vector<block> &otMsgRecover)
    {
        if (decKey.size() != otMsgPairSize || choices.size() != otMsgPairSize ||
            otMsgCiphers.size() != otMsgPairSize)
        {
            print_error(-6);
            return -6;
        }
        otMsgRecover.resize(otMsgPairSize);
        for (int i = 0; i < otMsgPairSize; i++)
        {
            u8 r = choices[i];
            otMsgRecover[i] = otMsgCiphers[i][r] ^ decKey[i];
        }
        return 0;
    }
}

#endif

////test////
#ifdef NP99_TEST
namespace oc = osuCrypto;
// #include <vector>
#include "naorpinkas.h"
// using namespace std;
using namespace oc;
int main(int argc, char **argv)
{
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
    for (int i = 0; i < enckey.size(); i++)
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
    for (int i = 0; i < deckey.size(); i++)
    {
        cout << "i:" << i << " " << deckey[i] << endl;
    }
    // vector<oc::block> otMsgRecover;
    // flag = npReceiver.genOTRecover(deckey, rChoices, otMsgCipher, otMsgRecover);
    // cout << "6===>>flag:" << flag << endl;
    // cout << "===>>recover:" << otMsgRecover[0] << endl;
    // check_recover(otMsg, rChoices, otMsgRecover);
    return 0;
}
#endif