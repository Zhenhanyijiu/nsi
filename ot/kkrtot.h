#ifndef __KKRTOT_H__
#define __KKRTOT_H__
#include "Common/BitVector.h"
#include "Common/MatrixView.h"
#include "iknpote.h"
#include <array>
#include <vector>
#ifdef __cplusplus
extern "C"
{
#endif

    namespace osuCrypto
    {
        //kkrtot sender
        class KkrtOtSender
        {
        private:
            IknpOtExtReceiver iknpRecevier;
            std::vector<PRNG> mGens;
            BitVector mBaseChoiceBits;
            std::vector<block> mChoiceBlks;
            MatrixView<block> mT;
            MatrixView<block> mCorrectionVals;
            u64 mCorrectionIdx;
            u64 inputBlockSize; //4block
            u64 baseOtCount;    //512

        public:
            KkrtOtSender();
            ~KkrtOtSender();
            int init(PRNG &rng, bool maliciousSecure, u64 compSecParm);
            int kkrtGenPublicParamFromNpot(u8 **pubParamBuf, u64 *pubParamBufByteSize);
            int kkrtGetEncKeyFromNpot(u8 *pk0Buf, const u64 pk0BufSize);
            int kkrtGenRecoverMsg(const BitVector &choicesWidthInput,
                                  vector<block> &recoverMsgWidthOutput,
                                  vector<block> &uBuffOutput);
        };

        //kkrtot receiver
        class KkrtOtReceiver
        {
        private:
            /* data */
        public:
            KkrtOtReceiver();
            ~KkrtOtReceiver();
        };

    }
#ifdef __cplusplus
}
#endif
#endif