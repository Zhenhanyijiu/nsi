#pragma once
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include "naorpinkas.h"
namespace osuCrypto
{
    //基本OT次数固定为128
    //通过基本OT的交互式协议生成双方
    const u64 gOtExtBaseOtCount(128);
    //iknp-ot-ext 接收方结构
    class IknpOtExtReceiver
    {
    private:
        //iknp扩展协议的接收者，需要调用np-ot的发送方接口进行交互
        NaorPinkasSender npsender;
        std::array<std::array<PRNG, 2>, gOtExtBaseOtCount> mGens;
        //设iknp协议接收方，要接收n个消息,r=r1,r2,...,rn

    public:
        IknpOtExtReceiver();
        ~IknpOtExtReceiver();
        //IknpOtExtReceiver初始化
        int init(PRNG &rng, const u32 otMsgPairSize = gOtExtBaseOtCount,
                 const u32 otPerMsgBitSize = 128);
        //生成公共参数，并发送给对方
        int genPublicParamFromNpot(u8 **pubParamBuf, u64 *pubParamBufByteSize);
        //从对方接收pk0Bufs,并生成encKey,存到mGens中，备用
        int getEncKeyFromNpot(u8 *pk0Buf, const u64 pk0BufSize);
        //输入的bitvector为choicesWidth,外部初始化大小
        int genRecoverMsg(const BitVector &choicesWidthInput,
                          vector<block> &recoverMsgWidthOutput, vector<block> &uBuffOutput);
    };
    /*************IknpOtExtSender*************/
    //iknp-ot-ext 发送方结构
    class IknpOtExtSender
    {
    private:
        NaorPinkasReceiver npreceiver;
        std::array<PRNG, gOtExtBaseOtCount> mGens;
        //128,随机选取128bit作为npot接收方的输入
        BitVector mBaseChoiceBits;

    public:
        IknpOtExtSender();
        ~IknpOtExtSender();
        //初始化IknpOtExtSender
        int init(PRNG &rng, const u32 otMsgPairSize = gOtExtBaseOtCount,
                 const u32 otPerMsgBitSize = 128);
        //接收对方发送过来的公共参数，并根据choices输入生成pk0s,并发送过对方
        int genPK0FromNpot(u8 *pubParamBuf, const u64 pubParamBufByteSize,
                           u8 **pk0Buf, u64 *pk0BufSize);
        //uBuffInput对方发送过来的，作为输入，encMsgOutput为输出，大小在外部初始化
        int getEncMsg(const vector<block> &uBuffInput, vector<array<block, 2>> &encMsgOutput);
    };

}