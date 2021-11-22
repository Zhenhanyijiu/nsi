#pragma once
// This file and the associated implementation has been placed in the public domain, waiving all copyright. No restrictions are placed on its use.
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
// #include <cryptoTools/Crypto/RCurve.h>
#include <cryptoTools/Crypto/Curve.h>
#include <cryptoTools/Common/BitVector.h>
// #define ENABLE_MIRACL
// #if defined ENABLE_RELIC || defined ENABLE_MIRACL
#define NAOR_PINKAS
using namespace std;
namespace osuCrypto
{
    // #ifdef ENABLE_RELIC
    //     using Curve = REllipticCurve;
    //     using Point = REccPoint;
    //     using Brick = REccPoint;
    //     using Number = REccNumber;
    // #else
    // using Curve = EllipticCurve;
    // using Point = EccPoint;
    // using Brick = EccBrick;
    // using Number = EccNumber;
    // #endif
    //NP-OT-Sender
    class NaorPinkasSender
    {
    private:
        u32 otMsgPairSize;
        u32 otPerMsgBitSize;
        u32 numThreads;
        u32 nSndVals;
        PRNG prng;
        // EllipticCurve *curve;
        // EccNumber *alphaPtr;
        vector<u8> alphaPtr;
        block R;
        // std::vector<EccPoint> pC;
        // vector<vector<u8>> pC;
        vector<u8> pubPCParamBuf; //A,C param

    public:
        NaorPinkasSender();
        ~NaorPinkasSender();
        int init(PRNG &rng, const u32 otMsgPairSize = 1,
                 const u32 otPerMsgBitSize = 128);
        //对于发送方,生成公共参数A,C
        int genPublicParam(u8 **pubParamBuf, u64 *pubParamBufByteSize);
        //一次ot，此协议只要传输一次pk0即可;如果encKey长度大于1，说明要发送的消息有多对；
        //encKey 存放ot最后一次传输所用的加密密钥
        int getEncKey(u8 *pk0Buf, const u64 pk0BufSize,
                      vector<array<block, 2>> &encKey);
        //这里先按照要OT传输的消息大小为一个block
        int genOTCipher(const vector<array<block, 2>> &encKey,
                        const vector<array<block, 2>> &otMessage,
                        vector<array<block, 2>> &otMsgCiphers);
    };
    //NP-OT-Receiver
    class NaorPinkasReceiver
    {
    private:
        u32 otMsgPairSize;
        u32 otPerMsgBitSize;
        u32 numThreads;
        u32 nSndVals;
        PRNG prng;
        // EllipticCurve *curve;
        // std::vector<EccPoint> pC;
        std::vector<u8> pC;
        // vector<EccNumber> sks;
        vector<vector<u8>> sks;
        vector<u8> pk0sBuf;

    public:
        NaorPinkasReceiver();
        ~NaorPinkasReceiver();
        int init(PRNG &rng, const u32 otMsgPairSize = 1,
                 const u32 otPerMsgBitSize = 128);
        int genPK0(u8 *pubParamBuf, const u64 pubParamBufByteSize,
                   const BitVector &choices, u8 **pk0Buf, u64 *pk0BufSize);
        int getDecKey(vector<block> &decKey);
        int genOTRecover(const vector<block> &decKey, const BitVector &choices,
                         const vector<array<block, 2>> &otMsgCiphers,
                         vector<block> &otMsgRecover);
    };
}
// #endif