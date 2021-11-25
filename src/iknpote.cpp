#include "iknpote.h"
#include <Tools/Tools.h>
namespace osuCrypto
{
    static const u64 commStepSize(512);
    static const u64 superBlkSize(8);
    /*******class*******/
    IknpOtExtReceiver::IknpOtExtReceiver() {}
    IknpOtExtReceiver::~IknpOtExtReceiver() {}
    int IknpOtExtReceiver::init(PRNG &rng, const u32 otMsgPairSize,
                                const u32 otPerMsgBitSize)
    {
        return this->npsender.init(rng, otMsgPairSize, otPerMsgBitSize);
    }
    int IknpOtExtReceiver::genPublicParamFromNpot(u8 **pubParamBuf, u64 *pubParamBufByteSize)
    {
        return this->npsender.genPublicParam(pubParamBuf, pubParamBufByteSize);
    }
    int IknpOtExtReceiver::getEncKeyFromNpot(u8 *pk0Buf, const u64 pk0BufSize)
    {
        vector<array<block, 2>> encKey;
        int fg = 0;
        fg = this->npsender.getEncKey(pk0Buf, pk0BufSize, encKey);
        if (fg != 0)
        {
            return fg;
        }
        u64 encKeySize = encKey.size();
        if (gOtExtBaseOtCount != encKeySize)
        {
            return -10;
        }
        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            this->mGens[i][0].SetSeed(encKey[i][0]);
            this->mGens[i][1].SetSeed(encKey[i][1]);
            // cout << "第" << i + 1 << "对消息：\n";
            // cout << "" << (0) << ":" << encKey[i][0] << endl;
            // cout << "" << (1) << ":" << encKey[i][1] << endl;
        }
        return 0;
    }
    int IknpOtExtReceiver::genRecoverMsg(const BitVector &choicesWidthInput,
                                         vector<block> &recoverMsgWidthOutput,
                                         vector<block> &uBuffOutput)
    {
        //iknp接收方实际输入的iknpote的个数
        u64 rChoicesSize = choicesWidthInput.size();
        if (rChoicesSize < 0)
        {
            return -11;
        }
        //((60+128-1)/128)*128
        //步长128bit
        u64 numOtExt = roundUpTo(choicesWidthInput.size(), 128);
        //numSuperBlocks与numOtExt有一定的对应关系
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        //numBlocks==8,16,24,...
        u64 numBlocks = numSuperBlocks * superBlkSize;
        BitVector choices2(numBlocks * 128);
        choices2 = choicesWidthInput;
        //8*128为一个单位，不小于实际的输入长度rChoicesSize
        choices2.resize(numBlocks * 128);
        printf("[iknp recv] choices2 len:%d bytes\n", choices2.sizeBytes());
        cout << "[iknp recv] choices2 val:" << choices2 << endl;
        //转化为block类型
        // vector<block> choiceBlocks(numBlocks);
        // auto choiceBlocks = (block *)(choices2.data());
        auto choiceBlocks = choices2.getArrayView<block>();
        // .getArrayView<block>();
        // memcpy((char *)choiceBlocks.data(), choices2.data(), numBlocks * 128);
        for (int i = 0; i < numBlocks; i++)
        {
            cout << choiceBlocks[i] << endl;
        }
#if 0 //debug
        for (int i = 0; i < choiceBlocks.size(); i++)
        {
            cout << "===>>choiceBlock i:" << i << "," << choiceBlocks[i] << endl;
        }
#endif
        //定义t0矩阵
        std::array<std::array<block, superBlkSize>, 128> t0;
        // the index of the OT that has been completed.
        //初始化recoverMsgWidthOutput大小
        recoverMsgWidthOutput.resize(rChoicesSize);
        auto mIter = recoverMsgWidthOutput.begin();
        u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        //初始化uBuffOutput大小
        uBuffOutput.resize(step * 128 * superBlkSize);
        // get an array of blocks that we will fill.
        auto uIter = (block *)uBuffOutput.data();
        auto uEnd = uIter + uBuffOutput.size();
        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {
            // this will store the next 128 rows of the matrix u
            block *tIter = (block *)t0.data();
            block *cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the column indexed by colIdx. This is done with
                // AES in counter mode acting as a PRNG. We don'tIter use the normal
                // PRNG interface because that would result in a data copy when
                // we move it into the T0,T1 matrices. Instead we do it directly.
                //生成矩阵t0
                this->mGens[colIdx][0].mAes.ecbEncCounterMode(this->mGens[colIdx][0].mBlockIdx,
                                                              superBlkSize, tIter);
                //生成矩阵u,并将u^r^t发送给对方
                this->mGens[colIdx][1].mAes.ecbEncCounterMode(this->mGens[colIdx][1].mBlockIdx,
                                                              superBlkSize, uIter);
                // increment the counter mode idx.
                this->mGens[colIdx][0].mBlockIdx += superBlkSize;
                this->mGens[colIdx][1].mBlockIdx += superBlkSize;
                //u^c
                uIter[0] = uIter[0] ^ cIter[0];
                uIter[1] = uIter[1] ^ cIter[1];
                uIter[2] = uIter[2] ^ cIter[2];
                uIter[3] = uIter[3] ^ cIter[3];
                uIter[4] = uIter[4] ^ cIter[4];
                uIter[5] = uIter[5] ^ cIter[5];
                uIter[6] = uIter[6] ^ cIter[6];
                uIter[7] = uIter[7] ^ cIter[7];
                //u=u^c^t
                uIter[0] = uIter[0] ^ tIter[0];
                uIter[1] = uIter[1] ^ tIter[1];
                uIter[2] = uIter[2] ^ tIter[2];
                uIter[3] = uIter[3] ^ tIter[3];
                uIter[4] = uIter[4] ^ tIter[4];
                uIter[5] = uIter[5] ^ tIter[5];
                uIter[6] = uIter[6] ^ tIter[6];
                uIter[7] = uIter[7] ^ tIter[7];

                uIter += 8;
                tIter += 8;
            }
            //如果 numSuperBlocks >512时，这里需要优化，不过一般512就足够了
            if (uIter == uEnd)
            {
                // send over u buffer
                // chl.asyncSend(std::move(uBuff));
                //512是一个大块
                u64 step = std::min<u64>(numSuperBlocks - superBlkIdx - 1, (u64)commStepSize);
                if (step)
                {
                    uBuffOutput.resize(step * 128 * superBlkSize);
                    uIter = (block *)uBuffOutput.data();
                    uEnd = uIter + uBuffOutput.size();
                }
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            sse_transpose128x1024(t0);

            //block* mStart = mIter;
            //block* mEnd = std::min<block*>(mIter + 128 * superBlkSize, &*messages.end());
            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, recoverMsgWidthOutput.end() - mIter);
            tIter = (block *)t0.data();
            block *tEnd = (block *)t0.data() + 128 * superBlkSize;
            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter) = *tIter;
                    tIter += superBlkSize;
                    mIter += 1;
                }
                tIter = tIter - 128 * superBlkSize + 1;
            }
            // #ifdef IKNP_DEBUG
            //             u64 doneIdx = mStart - messages.data();
            //             block *msgIter = messages.data() + doneIdx;
            //             chl.send(msgIter, sizeof(block) * 128 * superBlkSize);
            //             cIter = choiceBlocks.data() + superBlkSize * superBlkIdx;
            //             chl.send(cIter, sizeof(block) * superBlkSize);
            // #endif
            //doneIdx = stopIdx;
        }
#ifdef IKNP_SHA_HASH
        RandomOracle sha;
        u8 hashBuff[20];
#else
        std::array<block, 8> aesHashTemp;
#endif
        u64 doneIdx = (0);
        u64 bb = (recoverMsgWidthOutput.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(recoverMsgWidthOutput.size(), doneIdx + 128);

#ifdef IKNP_SHA_HASH
            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {
                // hash it
                sha.Reset();
                sha.Update((u8 *)&recoverMsgWidthOutput[doneIdx], sizeof(block));
                sha.Final(hashBuff);
                recoverMsgWidthOutput[doneIdx] = *(block *)hashBuff;
            }
#else
            auto length = stop - doneIdx;
            auto steps = length / 8;
            block *mIter = recoverMsgWidthOutput.data() + doneIdx;
            for (u64 i = 0; i < steps; ++i)
            {
                mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
                mIter[0] = mIter[0] ^ aesHashTemp[0];
                mIter[1] = mIter[1] ^ aesHashTemp[1];
                mIter[2] = mIter[2] ^ aesHashTemp[2];
                mIter[3] = mIter[3] ^ aesHashTemp[3];
                mIter[4] = mIter[4] ^ aesHashTemp[4];
                mIter[5] = mIter[5] ^ aesHashTemp[5];
                mIter[6] = mIter[6] ^ aesHashTemp[6];
                mIter[7] = mIter[7] ^ aesHashTemp[7];
                mIter += 8;
            }

            auto rem = length - steps * 8;
            mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
            for (u64 i = 0; i < rem; ++i)
            {
                mIter[i] = mIter[i] ^ aesHashTemp[i];
            }

            doneIdx = stop;
#endif
        }

        return 0;
    }
    /***********IknpOtExtSender*********/
    IknpOtExtSender::IknpOtExtSender() {}
    IknpOtExtSender::~IknpOtExtSender() {}
    int IknpOtExtSender::init(PRNG &rng, const u32 otMsgPairSize,
                              const u32 otPerMsgBitSize)
    {
        this->mBaseChoiceBits.resize(otMsgPairSize);
        this->mBaseChoiceBits.randomize(rng);
        return this->npreceiver.init(rng, otMsgPairSize, otPerMsgBitSize);
    }
    int IknpOtExtSender::genPK0FromNpot(u8 *pubParamBuf, const u64 pubParamBufByteSize,
                                        u8 **pk0Buf, u64 *pk0BufSize)
    {
        int fg = this->npreceiver.genPK0(pubParamBuf, pubParamBufByteSize,
                                         this->mBaseChoiceBits, pk0Buf, pk0BufSize);
        if (fg != 0)
        {
            return fg;
        }
        //并生成decKey,存到mGens中，备用
        // int getDecKeyFromNpot();
        /**********生成mGens start***********/
        vector<block> decKeys;
        fg = this->npreceiver.getDecKey(decKeys);
        if (fg != 0)
        {
            return fg;
        }
        if (decKeys.size() != gOtExtBaseOtCount)
        {
            return -11;
        }
        // cout << "vectorbit,choices:" << this->mBaseChoiceBits << endl;
        for (int i = 0; i < gOtExtBaseOtCount; i++)
        {
            this->mGens[i].SetSeed(decKeys[i]);
            // cout << "第" << i + 1 << "对消息：\n";
            // cout << "" << (0) << ":" << decKeys[i] << endl;
        }
        /**********生成mGens end  ***********/
        return 0;
    }
    // int IknpOtExtSender::getDecKeyFromNpot()
    // {
    //     vector<block> decKeys;
    //     int fg = this->npreceiver.getDecKey(decKeys);
    //     if (fg != 0)
    //     {
    //         return fg;
    //     }
    //     if (decKeys.size() != gOtExtBaseOtCount)
    //     {
    //         return -11;
    //     }
    //     // cout << "vectorbit,choices:" << this->mBaseChoiceBits << endl;
    //     for (int i = 0; i < gOtExtBaseOtCount; i++)
    //     {
    //         this->mGens[i].SetSeed(decKeys[i]);
    //         // cout << "第" << i + 1 << "对消息：\n";
    //         // cout << "" << (0) << ":" << decKeys[i] << endl;
    //     }
    //     return 0;
    // }
    int IknpOtExtSender::getEncMsg(const vector<block> &uBuffInput,
                                   vector<array<block, 2>> &encMsgOutput)
    {
        // round up
        u64 numOtExt = roundUpTo(encMsgOutput.size(), 128);
        u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        // u64 numSuperBlocks = (numOtExt / 128 + superBlkSize - 1) / superBlkSize;
        u64 step = std::min<u64>(numSuperBlocks, (u64)commStepSize);
        //u64 numBlocks = numSuperBlocks * superBlkSize;
        // a temp that will be used to transpose the sender's matrix
        std::array<std::array<block, superBlkSize>, 128> t;
        // std::vector<std::array<block, superBlkSize>> u(128 * commStepSize);

        std::array<block, 128> choiceMask;
        block delta = *(block *)this->mBaseChoiceBits.data();
        for (u64 i = 0; i < gOtExtBaseOtCount; ++i)
        {
            if (this->mBaseChoiceBits[i])
                choiceMask[i] = AllOneBlock;
            else
                choiceMask[i] = ZeroBlock;
        }

        auto mIter = encMsgOutput.begin();

        // block *uIter = (block *)u.data() + superBlkSize * 128 * commStepSize;
        u64 uBuffInputSize = uBuffInput.size();
        //check ok
        if (uBuffInputSize != step * 128 * superBlkSize)
        {
            return -121;
        }
        block *uIter = (block *)uBuffInput.data();
        block *uEnd = uIter + uBuffInputSize;

        for (u64 superBlkIdx = 0; superBlkIdx < numSuperBlocks; ++superBlkIdx)
        {

            block *tIter = (block *)t.data();
            block *cIter = choiceMask.data();
            // if (uIter == uEnd)
            // {
            //     u64 step = std::min<u64>(numSuperBlocks - superBlkIdx, (u64)commStepSize);
            //     // chl.recv((u8 *)u.data(), step * superBlkSize * 128 * sizeof(block));
            //     uIter = (block *)u.data();
            // }
            // transpose 128 columns at at time. Each column will be 128 * superBlkSize = 1024 bits long.
            for (u64 colIdx = 0; colIdx < 128; ++colIdx)
            {
                // generate the columns using AES-NI in counter mode.
                //生成t
                this->mGens[colIdx].mAes.ecbEncCounterMode(this->mGens[colIdx].mBlockIdx,
                                                           superBlkSize, tIter);
                this->mGens[colIdx].mBlockIdx += superBlkSize;

                uIter[0] = uIter[0] & *cIter;
                uIter[1] = uIter[1] & *cIter;
                uIter[2] = uIter[2] & *cIter;
                uIter[3] = uIter[3] & *cIter;
                uIter[4] = uIter[4] & *cIter;
                uIter[5] = uIter[5] & *cIter;
                uIter[6] = uIter[6] & *cIter;
                uIter[7] = uIter[7] & *cIter;

                tIter[0] = tIter[0] ^ uIter[0];
                tIter[1] = tIter[1] ^ uIter[1];
                tIter[2] = tIter[2] ^ uIter[2];
                tIter[3] = tIter[3] ^ uIter[3];
                tIter[4] = tIter[4] ^ uIter[4];
                tIter[5] = tIter[5] ^ uIter[5];
                tIter[6] = tIter[6] ^ uIter[6];
                tIter[7] = tIter[7] ^ uIter[7];

                ++cIter;
                uIter += 8;
                tIter += 8;
            }

            // transpose our 128 columns of 1024 bits. We will have 1024 rows,
            // each 128 bits wide.
            sse_transpose128x1024(t);

            auto mEnd = mIter + std::min<u64>(128 * superBlkSize, encMsgOutput.end() - mIter);
            tIter = (block *)t.data();
            block *tEnd = (block *)t.data() + 128 * superBlkSize;
            while (mIter != mEnd)
            {
                while (mIter != mEnd && tIter < tEnd)
                {
                    (*mIter)[0] = *tIter;         //qi
                    (*mIter)[1] = *tIter ^ delta; //qi^s

                    tIter += superBlkSize;
                    mIter += 1;
                }
                tIter = tIter - 128 * superBlkSize + 1;
            }

            // #ifdef IKNP_DEBUG
            //             BitVector choice(128 * superBlkSize);
            //             chl.recv(u.data(), superBlkSize * 128 * sizeof(block));
            //             chl.recv(choice.data(), sizeof(block) * superBlkSize);
            //             u64 doneIdx = mStart - messages.data();
            //             u64 xx = std::min<u64>(i64(128 * superBlkSize), (messages.data() + messages.size()) - mEnd);
            //             for (u64 rowIdx = doneIdx,
            //                      j = 0;
            //                  j < xx; ++rowIdx, ++j)
            //             {
            //                 if (neq(((block *)u.data())[j], messages[rowIdx][choice[j]]))
            //                 {
            //                     std::cout << rowIdx << std::endl;
            //                     throw std::runtime_error("");
            //                 }
            //             }
            // #endif
        }

#ifdef IKNP_SHA_HASH
        RandomOracle sha;
        u8 hashBuff[20];
        u64 doneIdx = 0;

        u64 bb = (encMsgOutput.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(encMsgOutput.size(), doneIdx + 128);

            for (u64 i = 0; doneIdx < stop; ++doneIdx, ++i)
            {
                // hash the message without delta
                sha.Reset();
                sha.Update((u8 *)&encMsgOutput[doneIdx][0], sizeof(block));
                sha.Final(hashBuff);
                encMsgOutput[doneIdx][0] = *(block *)hashBuff;

                // hash the message with delta
                sha.Reset();
                sha.Update((u8 *)&encMsgOutput[doneIdx][1], sizeof(block));
                sha.Final(hashBuff);
                encMsgOutput[doneIdx][1] = *(block *)hashBuff;
            }
        }
#else

        std::array<block, 8> aesHashTemp;

        u64 doneIdx = 0;
        u64 bb = (encMsgOutput.size() + 127) / 128;
        for (u64 blockIdx = 0; blockIdx < bb; ++blockIdx)
        {
            u64 stop = std::min<u64>(encMsgOutput.size(), doneIdx + 128);

            auto length = 2 * (stop - doneIdx);
            auto steps = length / 8;
            block *mIter = encMsgOutput[doneIdx].data();
            for (u64 i = 0; i < steps; ++i)
            {
                mAesFixedKey.ecbEncBlocks(mIter, 8, aesHashTemp.data());
                mIter[0] = mIter[0] ^ aesHashTemp[0];
                mIter[1] = mIter[1] ^ aesHashTemp[1];
                mIter[2] = mIter[2] ^ aesHashTemp[2];
                mIter[3] = mIter[3] ^ aesHashTemp[3];
                mIter[4] = mIter[4] ^ aesHashTemp[4];
                mIter[5] = mIter[5] ^ aesHashTemp[5];
                mIter[6] = mIter[6] ^ aesHashTemp[6];
                mIter[7] = mIter[7] ^ aesHashTemp[7];

                mIter += 8;
            }

            auto rem = length - steps * 8;
            mAesFixedKey.ecbEncBlocks(mIter, rem, aesHashTemp.data());
            for (u64 i = 0; i < rem; ++i)
            {
                mIter[i] = mIter[i] ^ aesHashTemp[i];
            }

            doneIdx = stop;
        }
#endif
        return 0;
    }
}

#ifdef IKNP_TEST
namespace oc = osuCrypto;
// #include <vector>
#include "iknpote.h"
// using namespace std;
using namespace oc;
void check_iknp(vector<array<block, 2>> &enckey, vector<block> &deckey, BitVector &rChoices)
{
    printf("enckey lens:%ld,deckey lens:%ld,rChoices lens:%ld\n",
           enckey.size(), deckey.size(), rChoices.size());
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
int test_iknp(int width)
{
    oc::PRNG rng(oc::toBlock(0x1122334455));
    //iknp 接收者
    oc::IknpOtExtReceiver iknpReceiver;
    iknpReceiver.init(rng);
    oc::u8 *pubParamBuf = nullptr;
    oc::u64 pubParamBufSize = 0;
    iknpReceiver.genPublicParamFromNpot(&pubParamBuf, &pubParamBufSize);
    //iknp 发送者
    oc::IknpOtExtSender iknpSender;
    iknpSender.init(rng); //默认128对
    oc::u8 *pk0buf = nullptr;
    oc::u64 pk0bufSize = 0;
    iknpSender.genPK0FromNpot(pubParamBuf, pubParamBufSize, &pk0buf, &pk0bufSize);
    //iknp receiver
    iknpReceiver.getEncKeyFromNpot(pk0buf, pk0bufSize);
    //iknp sender
    // iknpSender.getDecKeyFromNpot();
    // int width = 100;
    oc::BitVector choicesWidthInput(width);
    oc::PRNG rng11(oc::toBlock(0x1c5c168c24ef694909174dbde7103554));
    choicesWidthInput.randomize(rng11);
    vector<oc::block> recoverMsgWidthOutput;
    vector<oc::block> uBuffOutput;
    //iknp receiver
    int fg = iknpReceiver.genRecoverMsg(choicesWidthInput, recoverMsgWidthOutput,
                                        uBuffOutput);
    if (fg)
    {
        printf("1====error:%d\n", fg);
        return -1;
    }
    // for (int i = 0; i < recoverMsgWidthOutput.size(); i++)
    for (int i = 0; i < 4; i++)
    {
        cout << "i:" << i << "," << recoverMsgWidthOutput[i] << endl;
    }
    // printOTMsgSingle(recoverMsgWidthOutput);
    // cout << "===choicesWidthInput:" << choicesWidthInput << endl;
    //iknp sender
    vector<array<oc::block, 2>> encMsgOutput(width);
    fg = iknpSender.getEncMsg(uBuffOutput, encMsgOutput);
    if (fg)
    {
        printf("2====error:%d\n", fg);
        return -1;
    }
    for (int i = 0; i < 4; i++)
    {
        cout << "i:" << i << ",0:" << encMsgOutput[i][0] << endl;
        cout << "i:" << i << ",1:" << encMsgOutput[i][1] << endl;
    }
    check_iknp(encMsgOutput, recoverMsgWidthOutput, choicesWidthInput);
    // int *p = new (int);内存泄漏测试语句
    return 0;
}
int main(int argc, char *argv[])
{
    int width = 100;
    if (argc != 1)
    {
        width = atoi(argv[1]);
    }
    for (int i = 0; i < 10; i++)
    {
        test_iknp(width);
    }
    return 0;
}
#endif