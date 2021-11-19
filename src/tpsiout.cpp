
#include <iostream>
#include "Network/BtChannel.h"
#include "Network/BtEndpoint.h"

using namespace std;
#include "Common/Defines.h"
using namespace osuCrypto;

#include "OtBinMain.h"
#include "OtBinMain.v2.h"
#include "bitPosition.h"

#include <numeric>
#include "Common/Log.h"
#include "gbf.h"
#include "o1party.h"
#include "tpsi.h"
#include "psi3.h"
#include "tpsiout.h"
#include <stdio.h>
//int miraclTestMain();
inline void tpsi_party_fudata(u64 myIdx, u64 nParties, u64 threshold, u64 setSize,
							  std::vector<std::vector<char>> ip_array,
							  std::vector<std::vector<u32>> port_array,
							  std::vector<std::vector<u8>> data_set,
							  std::vector<u64> &mIntersection,
							  u64 type_okvs, u64 type_security);
int tpsi_process(u64_t p_idx, u64_t set_size,
				 std::vector<std::vector<char>> ip_array,
				 std::vector<std::vector<u32_t>> port_array,
				 std::vector<std::vector<u8_t>> data_set,
				 std::vector<u64_t> *psi_results_output)
{
	// tpsi_party_fudata(pIdx, 3, 2, 10000, GbfOkvs, secSemiHonest);
	tpsi_party_fudata(p_idx, 3, 2, set_size,
					  ip_array,
					  port_array,
					  data_set,
					  *psi_results_output,
					  SimulatedOkvs, secSemiHonest);
	return 0;
}
//
inline void tpsi_party_fudata(u64 myIdx, u64 nParties, u64 threshold, u64 setSize,
							  std::vector<std::vector<char>> ip_array,
							  std::vector<std::vector<u32>> port_array,
							  std::vector<std::vector<u8>> data_set,
							  std::vector<u64> &mIntersection,
							  u64 type_okvs, u64 type_security)
{
	//party 0--->(t-1) distributes key + value to central parties
	// party t computes all XOR F(k,value)
	// party t ---> n runs ZeroXOR

	u64 party_t_id = nParties - threshold; // party who computes XOR of all F(key, value) from users
										   //u64 num_users = party_t - 1; //party who sends each key to P_{<n-t} and sends F(key, value) to P_{n-t}
										   // std::vector<u64> mIntersection;

	// std::fstream textout;
	// textout.open("./runtime_" + myIdx, textout.app | textout.out);

#pragma region setup
	u64 psiSecParam = 40, bitSize = 128, numChannelThreads = 1, okvsTableSize = setSize;
	u64 party_n = nParties - 1; //party n-1 vs n
	Timer timer;
	PRNG prng(_mm_set_epi32(4253465, 3434565, myIdx, myIdx));
	u64 expected_intersection = 3; // (*(u64*)&prng.get<block>()) % setSize;

	if (type_okvs == SimulatedOkvs)
		okvsTableSize = okvsLengthScale * setSize;
	else if (type_okvs == PolyOkvs)
		okvsTableSize = setSize;
	else if (type_okvs == PaxosOkvs)
		okvsTableSize = setSize;

	std::string name("psi");
	BtIOService ios(0);
	std::vector<BtEndpoint> ep(nParties);
	std::vector<std::vector<Channel *>> chls(nParties);

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i < myIdx)
		{
			//myIdx=0,i=0,no;  i=1,no;   i=2,no
			//myIdx=1,i=0,1201;i=1,no;   i=2,no
			//myIdx=2,i=0,1202;i=1,1302; i=2,no
			// u32 port = 10200 + i * 100 + myIdx;
			//get the same port; i=1 & pIdx=2 =>port=102
			//channel bwt i and pIdx, where i is sender
			// ep[i].start(ios, ip_array[myIdx].data(), port_arrays[myIdx][i], false, name);
			char ip_char[32] = {0};
			memset(ip_char, 0, 32);
			memcpy(ip_char, ip_array[i].data(), ip_array[i].size());
			ep[i].start(ios, ip_char, port_array[myIdx][i], false, name);
			// ep[i].start(ios, ip_array[i].data(), port_arrays[myIdx][i], false, name);
			// ep[i].start(ios, ip_array[myIdx][i], port_arrays[myIdx][i], false, name);
		}
		else if (i > myIdx)
		{
			//myIdx=0,i=0,no;i=1,1201; i=2,1202
			//myIdx=1,i=0,no;i=1,no;   i=2,1302
			//myIdx=2,i=0,no;i=1,no;   i=2,no
			// u32 port = 10200 + myIdx * 100 + i;
			//get the same port; i=2 & pIdx=1 =>port=102
			//channel bwt i and pIdx, where i is receiver
			// ep[i].start(ios, ip_array[i].data(), port_arrays[myIdx][i], true, name);
			char ip_char[32] = {0};
			memset(ip_char, 0, 32);
			memcpy(ip_char, ip_array[myIdx].data(), ip_array[myIdx].size());
			printf("===in psi3_process_only,i:%d,curr_ip:%s\n", i, ip_char);
			ep[i].start(ios, ip_char, port_array[myIdx][i], true, name);
			// ep[i].start(ios, ip_array[myIdx].data(), port_arrays[myIdx][i], true, name);
			// ep[i].start(ios, "0", port_arrays[myIdx][i], true, name);
		}
	}
	printf("=============tpsi network end===========\n");

	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			chls[i].resize(numChannelThreads);
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j] = &ep[i].addChannel(name, name);
		}
	}

	u64 maskSize = roundUpTo(psiSecParam + 2 * std::log2(setSize) - 1, 8) / 8;

	// PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045)), prngDiff(_mm_set_epi32(434653, 23, myIdx, myIdx));
	std::vector<block> inputSet(setSize);
	SHA1 sha1_hash;
	u8 output[20];
	for (u64 i = 0; i < setSize; i++)
	{
		// memcpy((char *)(inputSet.data() + i), data_set[i].data(), 16);
		sha1_hash.Reset();
		sha1_hash.Update(data_set[i].data(), data_set[i].size());
		sha1_hash.Final(output);
		inputSet[i] = *(block *)output;
	}
	printf("=========>>hash计算OK\n");

	// for (u64 i = 0; i < expected_intersection; ++i)
	// 	inputSet[i] = prngSame.get<block>();

	// for (u64 i = expected_intersection; i < setSize; ++i)
	// 	inputSet[i] = prngDiff.get<block>();
#pragma endregion

	u64 num_threads = nParties - 1; //for party 1

	timer.reset();

	auto timer_start = timer.setTimePoint("start");

	std::vector<block> aesSentKeys(nParties);		// each users generates aes key. Indeed, we only use aesKeys[t->n]
	std::vector<block> aesReceivedKeys(party_t_id); // Indeed, we only use aesKeys[0->t-1]

	std::vector<block> inputSet2ZeroXOR(setSize, ZeroBlock); //for party n-1 and n

	if (threshold < nParties - 1) //if t<n-1
	{
		//====================================
		//============sending and receiving aes keys========
		//Party $P_i$ for $i\in[1,v-1]$ chooses keys $\{k_i^j\}$ for $j\in[v+1,n]$ and sends $k_i^j$ to $P_j$
		if (myIdx < party_t_id) //user
		{
			for (u64 i = party_t_id + 1; i < nParties; ++i)
			{
				aesSentKeys[i] = prng.get<block>();					   //generating aes keys
				chls[i][0]->asyncSend(&aesSentKeys[i], sizeof(block)); //sending aesKeys[i] to party [t->n]

				//std::cout << IoStream::lock;
				//std::cout << aesSentKeys[i] << " - aesKeys[" << i << "] - myIdx" << myIdx << std::endl;
				//std::cout << IoStream::unlock;
			}
		}

		else if (myIdx < nParties && myIdx > party_t_id) //server
		{
			for (u64 i = 0; i < party_t_id; ++i)
			{
				chls[i][0]->recv(&aesReceivedKeys[i], sizeof(block)); //party [t->n] receives aesKey from party [0->t-1]
																	  //std::cout << IoStream::lock;
																	  //std::cout << aesReceivedKeys[i] << " - aesReceivedKey[" <<i<<"] - myIdx" << myIdx << std::endl;
																	  //std::cout << IoStream::unlock;
			}
		}

		//====================================
		//============compute encoding========

		/*std::cout << IoStream::lock;
		std::cout << inputSet[0] << " - inputSet - " << myIdx  << std::endl;
		std::cout << IoStream::unlock;*/

		auto timer_asekey_done = timer.setTimePoint("asekey_done");

		if (myIdx < party_t_id) //user computes XOR of all F(k, value) and encodes them before sending to party_t
		{
			std::vector<block> okvsTable; //okvs of party1
			user_encode(inputSet, aesSentKeys, okvsTable, party_t_id, nParties, type_okvs, type_security);
			chls[party_t_id][0]->send(okvsTable.data(), okvsTable.size() * sizeof(block)); //sending okvsTable to party_t

			auto timer_encode_done = timer.setTimePoint("distribute_done");

			/*	std::cout << IoStream::lock;
				for (u64 i = 0; i < okvsTable1.size(); i++)
					std::cout << okvsTable1[i] << " - " << i << "okvsTable1 party1_encode - " << myIdx << " ->" << party_n << std::endl;
				std::cout << IoStream::unlock;*/
		}

		else if (myIdx == party_t_id) //combined party
		{
			std::vector<block> hashInputSet(inputSet.size());
			hashInputSet = inputSet;
			if (type_security == secMalicious)
				mAesFixedKey.ecbEncBlocks(inputSet.data(), inputSet.size(), hashInputSet.data()); //H(xi)

			std::vector<std::vector<block>> okvsTables(party_t_id);	   //okvs of party 0->t
			std::vector<std::vector<block>> decOkvsTables(party_t_id); //okvs of party 0->t

			std::vector<std::thread> pThrds(party_t_id);
			for (u64 idxParty = 0; idxParty < pThrds.size(); ++idxParty)
			{
				pThrds[idxParty] = std::thread([&, idxParty]()
											   {
												   okvsTables[idxParty].resize(okvsTableSize);
												   chls[idxParty][0]->recv(okvsTables[idxParty].data(), okvsTables[idxParty].size() * sizeof(block)); //receving okvsTable from party 0->t
												   partyt_decode(hashInputSet, okvsTables[idxParty], decOkvsTables[idxParty], type_okvs, type_security);
											   });
			}
			for (u64 pIdx = 0; pIdx < pThrds.size(); ++pIdx)
				pThrds[pIdx].join();

			for (u64 idxParty = 0; idxParty < pThrds.size(); ++idxParty)
				for (u64 idxItem = 0; idxItem < inputSet.size(); ++idxItem)
					inputSet2ZeroXOR[idxItem] = decOkvsTables[idxParty][idxItem] ^ inputSet2ZeroXOR[idxItem]; //xor all values

			//partyt_decode(inputSet, okvsTables, inputSet2ZeroXOR, type_okvs, type_security);

			auto timer_encode_done = timer.setTimePoint("distribute_done");

			/*std::cout << IoStream::lock;
			for (u64 i = 0; i < 2; i++)
				std::cout << inputSet2ZeroXOR[i] << " - inputSet2ZeroXOR-t " << myIdx << std::endl;
			std::cout << IoStream::unlock;*/
		}

		else if (myIdx < nParties && myIdx > party_t_id) //server
		{
			std::vector<block> okvsTable; //okvs of each party 2 -> n-2
			server_prf(inputSet, aesReceivedKeys, inputSet2ZeroXOR, type_okvs, type_security);

			auto timer_encode_done = timer.setTimePoint("distribute_done");

			/*std::cout << IoStream::lock;
			for (u64 i = 0; i < 4; i++)
				std::cout << okvsTable[i] << " - okvsTable party2_encode: " << myIdx << " ->"<< party_n1 <<std::endl;
			std::cout << IoStream::unlock;*/
		}

		//====================================
		//============compute zeroXOR========

		//std::cout << IoStream::lock;
		//std::cout << party_t_id << " - party_t_id vs nParties" << nParties << std::endl;
		//std::cout << IoStream::unlock;
	}

	auto timer_server_start = timer.setTimePoint("timer_server_start");

	if (myIdx < nParties && myIdx >= party_t_id) //for zeroXOR
	{
		if (threshold == nParties - 1) //if t=n-1, payload = all zero
			inputSet2ZeroXOR.resize(setSize, ZeroBlock);
		/*testXORzero = inputSet2ZeroXOR[0];
		std::cout << IoStream::lock;
		std::cout << testXORzero << " before \t" << myIdx << "\n";
		std::cout << IoStream::unlock;*/

		zeroXOR_party(myIdx - party_t_id, threshold, nParties, chls, inputSet, inputSet2ZeroXOR, mIntersection, TableOPPRF, secSemiHonest);
	}
	auto timer_end = timer.setTimePoint("end");

	double dataSent = 0, dataRecv = 0, Mbps = 0, MbpsRecv = 0;
	for (u64 i = 0; i < nParties; ++i)
	{
		if (i != myIdx)
		{
			//chls[i].resize(numThreads);
			if (myIdx == nParties - 1 && i == party_t_id && threshold != nParties - 1)
			{
				//total communication cost is ~party_t(recv+sent) + (partyn-1)(recv+sent)
				//the above calculation consists of 2x the comm cost btw party_t and partyn-1
				// Thus, we do nothing here
			}
			else
			{
				dataSent += chls[i][0]->getTotalDataSent();
				dataRecv += chls[i][0]->getTotalDataRecv();
			}
		}
	}

	//if (threshold != nParties - 1)
	//{
	if (myIdx == 0)
	{
		std::cout << IoStream::lock;
		std::cout << "Client running time: \n";
		std::cout << timer << std::endl;
		std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
		std::cout << IoStream::unlock;
	}

	if (myIdx == party_t_id)
	{
		std::cout << "party t running time: \n";
		std::cout << timer << std::endl;
		std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	}

	if (myIdx == nParties - 1)
	{
		std::cout << IoStream::lock;
		std::cout << "last party running time: \n";
		std::cout << timer << std::endl;
		std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
		std::cout << IoStream::unlock;
	}
	//}
	//else
	//{
	//if (myIdx == 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "Client running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << "Comm: " << ((dataSent + dataRecv) / std::pow(2.0, 20)) << " MB" << std::endl;
	//	std::cout << IoStream::unlock;
	//}
	//if (myIdx == nParties - 1)
	//{
	//	std::cout << IoStream::lock;
	//	std::cout << "last party running time: \n";
	//	std::cout << timer << std::endl;
	//	std::cout << IoStream::unlock;
	//}

	//if (myIdx == 1)
	//	std::cout << "Total Comm: " << (((dataSent + dataRecv)*(nParties/2)) / std::pow(2.0, 20)) << " MB" << std::endl; //if t=n-1, total= each party*n/2

	//}/

	//total communication cost is ~party_t + (partyn-1)

	//close chanels
	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			for (u64 j = 0; j < numChannelThreads; ++j)
				chls[i][j]->close();

	for (u64 i = 0; i < nParties; ++i)
		if (i != myIdx)
			ep[i].stop();

	ios.stop();
}

void usage(const char *argv0)
{
	std::cout << "Error! Please use:" << std::endl;
	std::cout << "\t 1. For unit test: " << argv0 << " -u" << std::endl;
	std::cout << "\t 2. For simulation (5 parties <=> 5 terminals): " << std::endl;
	;
	std::cout << "\t\t each terminal: " << argv0 << " -n 5 -t 2 -m 12 -p [pIdx]" << std::endl;
}
#ifdef TPSI_TEST
int main(int argc, char **argv)
{

	u64 pSetSize = 5, psiSecParam = 40, bitSize = 128;

	u64 nParties, tParties, opt_basedOPPRF, setSize, isAug;

	u64 roundOPPRF;
	printf("======argc=:%d\n", argc);
	u64 pIdx = atoi(argv[1]);
	/////////////
	setSize = 100000;
	setSize = atoi(argv[2]);
	printf("===pIdx=%ld\n", pIdx);
	printf("===this is only 3 parties,size(%ld)\n", setSize);
	PRNG prngSame(_mm_set_epi32(4253465, 3434565, 234435, 23987045));
	PRNG prngDiff(_mm_set_epi32(434653, 23, pIdx, pIdx));
	u64 expected_intersection = 3000;
	expected_intersection = atoi(argv[3]);
	std::vector<std::vector<u8_t>> inputSet(setSize);
	for (u64 i = 0; i < expected_intersection; ++i)
	{ // inputSet[i] = prngSame.get<block>();
		inputSet[i].resize(16);
		prngSame.get(inputSet[i].data(), 16);
	}

	for (u64 i = expected_intersection; i < setSize; ++i)
	{ // inputSet[i] = prngDiff.get<block>();
		inputSet[i].resize(16);
		prngDiff.get(inputSet[i].data(), 16);
	}
	char *IP_S[3] = {"127.0.0.1", "127.0.0.2", "127.0.0.3"};
	std::vector<std::vector<char>> ip_arrary(3);
	for (int i = 0; i < 3; i++)
	{
		ip_arrary[i].resize(32);
		memset(ip_arrary[i].data(), 0, 32);
		memcpy(ip_arrary[i].data(), IP_S[i], strlen(IP_S[i]));
	}
	printf("===>>ip set end\n");
	/////////////
	std::vector<u64_t> psiResultsOutput;
	// long start1 = start_time();
	vector<vector<u32_t>> port_array(3);
	for (int i = 0; i < 3; i++)
	{
		port_array[i].resize(3);
		for (int j = 0; j <= i - 1; j++)
		{
			port_array[i][j] = port_array[j][i];
		}
		for (int j = i + 1; j < 3; j++)
		{
			port_array[i][j] = 12000 + i + j;
		}
	}
	tpsi_process(pIdx, setSize,
				 ip_arrary,
				 port_array,
				 inputSet,
				 &psiResultsOutput);
	// long start1_end = get_use_time(start1);
	printf("===>>外层获取求交数据个数:%ld......\n",
		   psiResultsOutput.size());
	return 0;
	switch (argc)
	{

	case 9: //tPSI
		//cout << "9\n";
		printf(">>>>>>>>>>>>>>>start");
		if (argv[1][0] == '-' && argv[1][1] == 'm')
			setSize = 1 << atoi(argv[2]);
		else
		{
			cout << "setSize: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[3][0] == '-' && argv[3][1] == 'n')
			nParties = atoi(argv[4]);
		else
		{
			cout << "nParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[5][0] == '-' && argv[5][1] == 't')
			tParties = atoi(argv[6]);
		else
		{
			cout << "tParties: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		if (argv[7][0] == '-' && argv[7][1] == 'p')
		{
			u64 pIdx = atoi(argv[8]);
			//cout << setSize << " \t"  << nParties << " \t" << tParties << "\t" << pIdx << "\n";
			//tpsi_party(pIdx, nParties, tParties, setSize, PaxosOkvs, secSemiHonest);
			printf("============");
			// tpsi_party(pIdx, nParties, tParties, setSize, SimulatedOkvs, secSemiHonest);
		}
		else
		{
			cout << "pIdx: wrong format\n";
			usage(argv[0]);
			return 0;
		}

		break;
	}

	return 0;
}

#endif