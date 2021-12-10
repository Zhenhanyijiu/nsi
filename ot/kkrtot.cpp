#include "kkrtot.h"
#include <cryptoTools/Crypto/PRNG.h>
namespace osuCrypto
{
    //kkrt sender
    KkrtOtSender::KkrtOtSender() {}
    KkrtOtSender::~KkrtOtSender() {}
    int KkrtOtSender::init(PRNG &rng, bool maliciousSecure, u64 compSecParm)
    {
        this->baseOtCount = roundUpTo(compSecParm * (maliciousSecure ? 7 : 4), 128);
        this->inputBlockSize = baseOtCount / 128;
        int fg = this->iknpRecevier.init(rng, 128, 128);
        if (fg)
        {
            return fg;
        }
        return 0;
    }
    int KkrtOtSender::kkrtGenPublicParamFromNpot(u8 **pubParamBuf,
                                                 u64 *pubParamBufByteSize)
    {
        int fg = this->iknpRecevier.genPublicParamFromNpot(pubParamBuf,
                                                           pubParamBufByteSize);
        if (fg)
        {
            return fg;
        }
        return 0;
    }

    int KkrtOtSender::kkrtGetEncKeyFromNpot(u8 *pk0Buf, const u64 pk0BufSize)
    {
        int fg = this->iknpRecevier.getEncKeyFromNpot(pk0Buf, pk0BufSize);
        if (fg)
        {
            return fg;
        }
        return 0;
    }

    //kkrt receiver
    KkrtOtReceiver::KkrtOtReceiver() {}
    KkrtOtReceiver::~KkrtOtReceiver() {}

}