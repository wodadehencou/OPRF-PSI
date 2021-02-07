
#include "PSI/include/Defines.h"
#include "PSI/include/PsiReceiver.h"
#include "PSI/include/PsiSender.h"
#include "PSI/include/utils.h"
#include "cryptoTools/Common/CLP.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Crypto/PRNG.h"
#include "cryptoTools/Network/Endpoint.h"
#include "cryptoTools/Network/IOService.h"
#include <emmintrin.h>
#include <fstream>
#include <stdio.h>

const std::string EP_NAME = "mp20_psi";

struct networkParams {
  bool networkServer;
  std::string address;
  int port;
};

// commadline arguments
std::vector<std::string> inFileOpt{"in"};
std::vector<std::string> outFileOpt{"out"};
std::vector<std::string> roleOpt{"role"};
std::vector<std::string> sendSizeOpt{"ss", "sendsize"};
std::vector<std::string> recvSizeOpt{"rs", "recvsize"};
std::vector<std::string> networkServerOpt{"server", "netserver"};
std::vector<std::string> addressOpt{"addr", "address"};
std::vector<std::string> portOpt{"port"};
std::vector<std::string> seedOpt{"seed"};
std::vector<std::string> commonSeedOpt{"commonseed"};
std::vector<std::string> maliciousSecureOpt{"malicious"};
std::vector<std::string> statSecOpt{"statsec"};
std::vector<std::string> helpOpt{"h", "help"};

void print_help() { std::cout << "help messages" << std::endl; }

// not supported ABCDEEF
osuCrypto::u64 hextoint(char in) {
  osuCrypto::u64 const x = in;
  return x < 58 ? x - 48 : x - 87;
}

// input file should contain only one column
// every column is a hex string of 128bit(16Byte, 32chars)
// MUST be lower case 0-9a-f
std::vector<osuCrypto::block> load_input(std::string fileName) {
  std::vector<osuCrypto::block> ret;

  FILE *fp = fopen(fileName.c_str(), "r");
  if (fp == NULL)
    exit(EXIT_FAILURE);

  char *line = NULL;
  size_t len = 0;
  while ((getline(&line, &len, fp)) != -1) {
    if (len < 32) {
      printf("length not valid line = %s", line);
      exit(EXIT_FAILURE);
    }
    // line must has fixed 32chars
    osuCrypto::u64 high =
        (hextoint(*line) << 60) | (hextoint(*(line + 1)) << 56) |
        (hextoint(*(line + 2)) << 52) | (hextoint(*(line + 3)) << 48) |
        (hextoint(*(line + 4)) << 44) | (hextoint(*(line + 5)) << 40) |
        (hextoint(*(line + 6)) << 36) | (hextoint(*(line + 7)) << 32) |
        (hextoint(*(line + 8)) << 28) | (hextoint(*(line + 9)) << 24) |
        (hextoint(*(line + 10)) << 20) | (hextoint(*(line + 11)) << 16) |
        (hextoint(*(line + 12)) << 12) | (hextoint(*(line + 13)) << 8) |
        (hextoint(*(line + 14)) << 4) | (hextoint(*(line + 15)) << 0);

    osuCrypto::u64 low =
        (hextoint(*(line + 16)) << 60) | (hextoint(*(line + 17)) << 56) |
        (hextoint(*(line + 18)) << 52) | (hextoint(*(line + 19)) << 48) |
        (hextoint(*(line + 20)) << 44) | (hextoint(*(line + 21)) << 40) |
        (hextoint(*(line + 22)) << 36) | (hextoint(*(line + 23)) << 32) |
        (hextoint(*(line + 24)) << 28) | (hextoint(*(line + 25)) << 24) |
        (hextoint(*(line + 26)) << 20) | (hextoint(*(line + 27)) << 16) |
        (hextoint(*(line + 28)) << 12) | (hextoint(*(line + 29)) << 8) |
        (hextoint(*(line + 30)) << 4) | (hextoint(*(line + 31)) << 0);

    ret.push_back(osuCrypto::toBlock(high, low));
  }
  fclose(fp);
  if (line)
    free(line);
  return ret;
}

void store_output(std::string fileName, std::vector<osuCrypto::block> set) {
  std::ofstream myFile;
  myFile.open(fileName);
  if (myFile.is_open()) {
    for (auto i = 0; i < set.size(); i++) {
      myFile << set[i] << std::endl;
    }
    myFile.close();
  } else {
    exit(EXIT_FAILURE);
  }
}

struct secParams {
  osuCrypto::u64 height;
  osuCrypto::u64 logHeight;
  osuCrypto::u64 width;
  osuCrypto::u64 hashLengthInBytes;
  osuCrypto::u64 h1LengthInBytes;
  osuCrypto::u64 bucket1;
  osuCrypto::u64 bucket2;
};

// TODO: need to manual compute
secParams generate_sec_params(osuCrypto::u64 sendSize, osuCrypto::u64 recvSize,
                              bool malicious, int statSec) {
  secParams ret;
  ret.logHeight = 20;
  ret.height = 1 << ret.logHeight;
  ret.width = 609;
  ret.hashLengthInBytes = 10;
  ret.h1LengthInBytes = 32;
  ret.bucket1 = 1 << 8;
  ret.bucket2 = 1 << 8;

  return ret;
}

void run_sender(osuCrypto::PRNG &rng, std::vector<osuCrypto::block> sendSet,
                osuCrypto::u64 sendSize, osuCrypto::u64 recvSize,
                networkParams *network, osuCrypto::block commonSeed,
                bool malicious, int statSec) {

  std::cout << "sender" << std::endl;

  secParams secp = generate_sec_params(sendSize, recvSize, malicious, statSec);

  osuCrypto::IOService ios;
  osuCrypto::Endpoint ep(ios, network->address, network->port,
                         network->networkServer ? osuCrypto::EpMode::Server
                                                : osuCrypto::EpMode::Client,
                         EP_NAME);
  osuCrypto::Channel sendChl = ep.addChannel();

  PSI::PsiSender psiSender;
  psiSender.run(rng, sendChl, commonSeed, sendSize, recvSize, secp.height,
                secp.logHeight, secp.width, sendSet, secp.hashLengthInBytes,
                secp.h1LengthInBytes, secp.bucket1, secp.bucket2);

  sendChl.close();
  ep.stop();
  ios.stop();
}

std::vector<osuCrypto::block>
run_receiver(osuCrypto::PRNG &rng, std::vector<osuCrypto::block> recvSet,
             osuCrypto::u64 sendSize, osuCrypto::u64 recvSize,
             networkParams *network, osuCrypto::block commonSeed,
             bool malicious, int statSec) {

  std::cout << "receiver" << std::endl;

  secParams secp = generate_sec_params(sendSize, recvSize, malicious, statSec);

  osuCrypto::IOService ios;
  osuCrypto::Endpoint ep(ios, network->address, network->port,
                         network->networkServer ? osuCrypto::EpMode::Server
                                                : osuCrypto::EpMode::Client,
                         EP_NAME);
  osuCrypto::Channel recvChl = ep.addChannel();

  PSI::PsiReceiver psiReceiver;
  std::vector<osuCrypto::u64> idx = psiReceiver.run(
      rng, recvChl, commonSeed, sendSize, recvSize, secp.height, secp.logHeight,
      secp.width, recvSet, secp.hashLengthInBytes, secp.h1LengthInBytes,
      secp.bucket1, secp.bucket2);

  //////////////// Output communication /////////////////
  // u64 sentData = recvChl.getTotalDataSent();
  // u64 recvData = recvChl.getTotalDataRecv();
  // u64 totalData = sentData + recvData;

  // std::cout << "Receiver sent communication: " << sentData / std::pow(2.0,
  // 20) << " MB\n"; std::cout << "Receiver received communication: " <<
  // recvData / std::pow(2.0, 20) << " MB\n"; std::cout << "Receiver total
  // communication: " << totalData / std::pow(2.0, 20) << " MB\n";

  recvChl.close();
  ep.stop();
  ios.stop();

  auto psi = idx.size();
  std::vector<osuCrypto::block> ret(psi);
  for (auto i = 0; i < psi; ++i) {
    ret[i] = recvSet[idx[i]];
  }

  return ret;
}

int main(int argc, char **argv) {
  osuCrypto::CLP cmd;
  cmd.parse(argc, argv);

  cmd.setDefault(portOpt, "21021");
  cmd.setDefault(addressOpt, "127.0.0.1");
  cmd.setDefault(statSecOpt, "40");

  if (cmd.isSet(helpOpt)) {
    print_help();
    return 0;
  }

  if (cmd.isSet(inFileOpt) == false || cmd.isSet(outFileOpt) == false ||
      cmd.isSet(roleOpt) == false || cmd.isSet(seedOpt) == false) {
    print_help();
    return 1;
  }

  std::string role = cmd.get<std::string>(roleOpt);
  bool networkServer = cmd.isSet(networkServerOpt);

  // set prng seed
  // std::vector<osuCrypto::u64> seeds = cmd.getMany<osuCrypto::u64>(seedOpt);
  std::vector<int> seeds = cmd.getMany<int>(seedOpt);
  seeds.resize(4);
  osuCrypto::PRNG prng;
  prng.SetSeed(_mm_set_epi32(seeds[0], seeds[1], seeds[2], seeds[3]));

  // get common prng seed
  std::vector<int> commonSeeds = cmd.getMany<int>(commonSeedOpt);
  commonSeeds.resize(4);
  osuCrypto::block commonSeed = _mm_set_epi32(commonSeeds[0], commonSeeds[1],
                                              commonSeeds[2], commonSeeds[3]);

  std::cout << "argument test pass" << std::endl;

  std::vector<osuCrypto::block> inSet =
      load_input(cmd.get<std::string>(inFileOpt));
  std::cout << "load input file pass" << std::endl;

  networkParams network{networkServer, cmd.get<std::string>(addressOpt),
                        cmd.get<int>(portOpt)};

  if (role == "sender") {
    if (cmd.isSet(recvSizeOpt) == false) {
      print_help();
      return 1;
    }
    run_sender(prng, inSet, inSet.size(), cmd.get<osuCrypto::u64>(recvSizeOpt),
               &network, commonSeed, cmd.isSet(maliciousSecureOpt),
               cmd.get<int>(statSecOpt));
  } else if (role == "receiver") {
    if (cmd.isSet(sendSizeOpt) == false) {
      print_help();
      return 1;
    }
    std::vector<osuCrypto::block> intersection =
        run_receiver(prng, inSet, cmd.get<osuCrypto::u64>(sendSizeOpt),
                     inSet.size(), &network, commonSeed,
                     cmd.isSet(maliciousSecureOpt), cmd.get<int>(statSecOpt));
    store_output(cmd.get<std::string>(outFileOpt), intersection);
  } else {
    print_help();
    return 1;
  }

  return 0;
}
