/*
 * A tool to import LLVM MC Disassembler on v7.0.0
 *
 * Based on play2.cpp (was for LLVM 3.4)
 * modified based on lib/MC/MCDisassembler/ *
 *
 * Changes:
 *    Use unique_ptr to replace pointers
 *    MemoryObject no longer exists, replaced with ArrayRef
 *    MCSubtargetInfo required in BAP_LLVMDisasmContext
 *    Include TargetSelect.h for initializers
 *
 * Implemented to be a local server that resolves incoming queries
 */


#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sstream>
#include <fstream>
#include <iostream>

#include <llvm/MC/MCAsmInfo.h>
#include <llvm/MC/MCContext.h>
#include <llvm/MC/MCDisassembler/MCDisassembler.h>
#include <llvm/MC/MCInstPrinter.h>
#include <llvm/MC/MCInstrInfo.h>
#include <llvm/MC/MCRegisterInfo.h>
#include <llvm/ADT/ArrayRef.h>
#include <llvm/Support/FormattedStream.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>

#include "capnp/resolver_in_cpp.capnp.h"
#include "capnp/resolver_out_cpp.capnp.h"
#include <capnp/message.h>
#include <capnp/serialize-packed.h>

using namespace llvm;

// Based on lib/MC/MCDisassembler/Disassembler.h
// Delete useless fields
struct BAP_LLVMDisasmContext {
  std::unique_ptr<const MCRegisterInfo> MRI;
  std::unique_ptr<const MCSubtargetInfo> MSI;
  std::unique_ptr<const MCInstrInfo> MII;
  std::unique_ptr<const MCDisassembler> DisAsm;
  std::unique_ptr<MCInstPrinter> IP;

  BAP_LLVMDisasmContext (const MCRegisterInfo *mRI, const MCSubtargetInfo *mSI,
                         const MCInstrInfo *mII, const MCDisassembler *disAsm,
                         MCInstPrinter *iP) {
    MRI.reset(mRI);
    MSI.reset(mSI);
    MII.reset(mII);
    DisAsm.reset(disAsm);
    IP.reset(iP);
  }
};
using BAP_LLVMDisasmContextRef = BAP_LLVMDisasmContext *;

// Based on lib/MC/MCDisassembler/MCDisassembler.cpp : LLVMCreateDisasmCPUFeatures
BAP_LLVMDisasmContextRef
BAP_LLVMCreateDisasmCPUFeatures (const char* TT, const char* CPU,
                                 void *DisInfo,
                                 LLVMOpInfoCallback GetOpInfo,
                                 LLVMSymbolLookupCallback SymbolLookUp) {
  // Get the target.
  std::string Error;
  const Target *TheTarget = TargetRegistry::lookupTarget(TT, Error);
  if (!TheTarget) {
    printf("lookupTarget failed\n");
    return nullptr;
  }

  const MCRegisterInfo *MRI = TheTarget->createMCRegInfo(TT);
  if (!MRI) {
    printf("createMCRegInfo failed\n");
    return nullptr;
  }

  // Get the assembler info needed to setup the MCContext.
  const MCAsmInfo *MAI = TheTarget->createMCAsmInfo(*MRI, TT);
  if (!MAI) {
    printf("createMCAsmInfo failed\n");
    return nullptr;
  }

  const MCInstrInfo *MII = TheTarget->createMCInstrInfo();
  if (!MII) {
    printf("createMCInstrInfo failed\n");
    return nullptr;
  }

  std::string Features;

  const MCSubtargetInfo *STI =
    TheTarget->createMCSubtargetInfo(TT, CPU, Features);
  if (!STI) {
    printf("createMCSubtargetInfo failed\n");
    return nullptr;
  }

  // Set up the MCContext for creating symbols and MCExpr's.
  auto Ctx = new MCContext(MAI, MRI, nullptr);
  // According to CLion, this is unreachable code
  /*if (!Ctx) {
    printf("new MCContext failed\n");
    return nullptr;
  }*/

  // Set up disassembler.
  MCDisassembler *DisAsm = TheTarget->createMCDisassembler(*STI, *Ctx);
  if (!DisAsm) {
    printf("createMCDisassembler failed\n");
    return nullptr;
  }

  std::unique_ptr<MCRelocationInfo> RelInfo(
    TheTarget->createMCRelocationInfo(TT, *Ctx));
  if (!RelInfo) {
    printf("createMCRelocationInfo failed\n");
    return nullptr;
  }

  std::unique_ptr<MCSymbolizer> Symbolizer(TheTarget->createMCSymbolizer(
    TT, GetOpInfo, SymbolLookUp, DisInfo, Ctx, std::move(RelInfo)));
  DisAsm->setSymbolizer(std::move(Symbolizer));

  // Set up the instruction printer.
  unsigned AsmPrinterVariant = MAI->getAssemblerDialect();
  MCInstPrinter *IP = TheTarget->createMCInstPrinter(
    Triple(TT), AsmPrinterVariant, *MAI, *MII, *MRI);
  if (!IP) {
    printf("createMCInstPrinter failed\n");
    return nullptr;
  }

  // Fields all created, return BAP_LLVMDisasmContextRef
  return new BAP_LLVMDisasmContext({MRI, STI, MII, DisAsm, IP});
}

// Based on lib/MC/MCDisassembler/MCDisassembler.cpp : LLVMCreateDisasmDispose
void BAP_LLVMDisasmDispose (BAP_LLVMDisasmContextRef DCR) {
  auto DC = static_cast<BAP_LLVMDisasmContext *>(DCR);
  delete DC;
}

// Based on lib/MC/MCDisassembler/MCDisassembler.cpp : LLVMDisasmInstruction
// Input a referenced Inst for the convenience of output.
size_t BAP_LLVMDisasmInstruction (BAP_LLVMDisasmContextRef DCR, uint8_t *Bytes,
                                  uint64_t BytesSize, uint64_t PC, MCInst &Inst,
                                  char *OutString, size_t OutStringSize) {
  auto DC = static_cast<BAP_LLVMDisasmContext *> (DCR);
  ArrayRef<uint8_t> Data(Bytes, BytesSize);

  uint64_t Size;
  const auto DisAsm = DC->DisAsm.get();
  auto IP = DC->IP.get();
  MCDisassembler::DecodeStatus S;
  SmallVector<char, 64> InsnStr;
  raw_svector_ostream Annotations(InsnStr);
  S = DisAsm -> getInstruction (Inst, Size, Data, PC, nulls(), Annotations);

  switch (S) {
    case MCDisassembler::Fail:
    case MCDisassembler::SoftFail: return 0;

    case MCDisassembler::Success: {
      StringRef AnnotationsStr = Annotations.str();

      SmallVector<char, 64> succInsn;
      raw_svector_ostream OS(succInsn);
      formatted_raw_ostream FormattedOS(OS);
      IP->printInst(&Inst, FormattedOS, AnnotationsStr, *DC->MSI);

      FormattedOS.flush();

      assert(OutStringSize != 0 && "Output buffer cannot be zero size");
      size_t OutputSize = std::min(OutStringSize-1, succInsn.size());
      std::memcpy(OutString, succInsn.data(), OutputSize);
      OutString[OutputSize] = '\0';

      return Size;
    }
  }
  llvm_unreachable("Invalid DecodeStatus!");
}

std::map<std::string, std::pair<std::string, int>> x86Prefixes = {
  //  {prefix, instruction_changed_to}
  {"\tlock\t", {"\tlock", 1}},
  {"\trepne\t", {"\trepne", 1}},
  {"\trepnz\t", {"\trepnz", 1}},
  {"\trep\t", {"\trep", 1}},
  {"\trepz\t", {"\trepz", 1}},
  {"\trepe\t", {"\trepe", 1}},
};

// Make one instruction ("prefix sth") into two instructions ("prefix" & "sth")
void PrefixIsolate (const std::string &platform, char* const str, size_t &inst_size) {
  if (platform == "i386" || platform == "x86_64") {
    // tries to match prefixes
    std::string instruction(str);
    for (auto const it : x86Prefixes) {
      auto &prefix = it.first;
      auto res = std::mismatch(prefix.begin(), prefix.end(), instruction.begin());
      if (res.first == prefix.end()) {
        // match succeeds, replace instruction
        auto inst = it.second.first;
        strcpy(str, inst.c_str());
        inst_size = it.second.second;
        return;
      }
    }
  }
}

// Check if an instruction contains only prefix instructions.
bool IsOnlyPrefix(const std::string &platform, char* const str) {
  if (platform == "i386" || platform == "x86_64") {
    // tries to match prefixes
    std::string instruction(str);
    while (instruction.length() > 0) {
      bool findMatch = false;
      for (auto it : x86Prefixes) {
        auto &prefix = it.second.first;
        auto res = std::mismatch(prefix.begin(), prefix.end(), instruction.begin());
        if (res.first == prefix.end()) {
          // match succeeds, cut instruction
          instruction = instruction.substr(prefix.length());
          findMatch = true;
          break;
        }
      }
      if (!findMatch) {
        return false;
      }
    }
    return true;
  }
  return false;
}

// -------------------- LLVM API above ------------------------

/* Common MTU / sizeof(capnp::word)*/
const size_t BUFF_SIZE = 160;
const size_t INST_SIZE = 32;
const size_t STR_SIZE = 128;
// Service path in Unix domain socket
std::string server_path_str ="/tmp/resolver.cpp.socket";
bool verbose = false;

bool disassem(const BAP_LLVMDisasmContextRef &DCR,
              const std::string &platform,
              const capnp::word* const in, const size_t &inSize,
              capnp::word* const out, size_t &outSize) {
  // Resolve in message
  kj::ArrayPtr<const capnp::word> inPtr(in, in + inSize);
  capnp::FlatArrayMessageReader inMsg(inPtr);
  ResolverIn::Reader inReader = inMsg.getRoot<ResolverIn>();

  // If has byte field, dis-assemble it
  if (inReader.hasBytes()) {
    // Init out structure
    capnp::MallocMessageBuilder outMsg;
    ResolverOut::Builder outBuilder = outMsg.initRoot<ResolverOut>();

    // Copy over from capnp type List to array
    uint8_t disBytes[INST_SIZE];
    auto bytes = inReader.getBytes();
    auto arySize = std::min(INST_SIZE, static_cast<size_t>(bytes.size()));
    for (size_t i = 0; i < arySize; ++i) disBytes[i] = bytes[i];

    std::stringstream totalString;
    int totalSize = 0;
    bool onlyPrefix, isNotInst = false;
    do {
      MCInst Inst;
      char outString[STR_SIZE]{};
      auto instSize = BAP_LLVMDisasmInstruction(DCR,
        disBytes + totalSize,
        arySize - totalSize,
        0,
        Inst,
        outString,
        STR_SIZE);
      if (instSize == 0) {
        isNotInst = true;
        break;
      }
      //PrefixIsolate(platform, outString, instSize); // fine-grain version
      // Check if instruction is coarse-grained
      totalString << outString;
      totalSize += instSize;
      onlyPrefix = IsOnlyPrefix(platform, outString);
    } while (onlyPrefix);

    if (isNotInst) {
      outBuilder.setIsInst(false);
    } else {
      std::string instString = totalString.str();
      if (verbose) std::cout << "\tInput resolved: " << instString << std::endl;
      outBuilder.setIsInst(true);
      outBuilder.setTakeBytes(static_cast<int32_t>(totalSize));
      outBuilder.setInst(instString);
    }

    auto outPtr = capnp::messageToFlatArray(outMsg);
    outSize = outPtr.end() - outPtr.begin();
    memcpy(out, outPtr.begin(), outSize * sizeof(capnp::word));
    if (verbose) {
      kj::ArrayPtr<capnp::word> rOutPtr(out, out + outSize);
      capnp::FlatArrayMessageReader rOutMsg(rOutPtr);
      ResolverOut::Reader outReader = rOutMsg.getRoot<ResolverOut>();
      std::cout<<"\tisInst: "<<outReader.getIsInst()<<std::endl;
      std::cout<<"\ttakesBytes: "<<outReader.getTakeBytes()<<std::endl;
      std::cout<<"\tOutput word size: "<<outSize<<std::endl;
    }
  }

  return inReader.getTerminate();
}

int main(int argc, char **argv) {
  // Arguments
  std::string platform;
  for (auto i = 1; i < argc; ++i) {
    if (std::string s(argv[i]); s == "-v") verbose = true;
    else if (s == "-f") {
      i ++;
      server_path_str = std::string(argv[i]);
    } else if ( s == "-p" ) {
      i ++;
      platform = std::string(argv[i]);
    }
  }

  // resolve
  if (platform == "i386" || platform == "x86" || platform == "x86_32" || platform == "x86-32") {
    platform = "i386";
  } else if (platform == "x86_64" || platform.empty() || platform == "x86-64" || platform == "amd64") {
    platform = "x86_64";
  } else {
    std::cout<<"unsupported platform: "<<platform<<std::endl;
    return 0;
  }

  // Create LLVM Disassembly object
  std::string tripleCPU[] = {platform, ""};
  InitializeAllTargetInfos();
  InitializeAllTargetMCs();
  InitializeAllDisassemblers();
  auto DCR = BAP_LLVMCreateDisasmCPUFeatures(tripleCPU[0].c_str(),
                                             tripleCPU[1].c_str(),
                                             nullptr, nullptr, nullptr);

  // Create a socket server
  int server = socket(AF_UNIX, SOCK_STREAM, 0);
  if (server <= 0) {
    perror("Socket create failed");
    exit(EXIT_FAILURE);
  }

  const char *server_path = server_path_str.c_str();

  sockaddr_un addr {};
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, server_path);
  unlink(server_path);
  if (bind(server, (sockaddr*)&addr,
           static_cast<socklen_t >(offsetof(sockaddr_un, sun_path) + strlen(addr.sun_path))) < 0) {
    perror("Socket bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server, 20) < 0) {
    perror("Socket listen failed");
    exit(EXIT_FAILURE);
  }

  if (verbose) std::cout<<"Server created as: "<<server_path<<std::endl;

  sockaddr_un cltAddr {};
  socklen_t cltAddrSize = sizeof(cltAddr);
  capnp::word inWord[BUFF_SIZE] {};
  capnp::word outWord[BUFF_SIZE] {};
  bool terminate = false;
  size_t outSize = 0;

  while (!terminate) {
    int client = accept(server, (sockaddr*)&cltAddr, &cltAddrSize);
    if (verbose) std::cout<<"Receive request from: "<<cltAddr.sun_path<<std::endl;
    auto msgSize = static_cast<size_t>(recv(client, inWord, BUFF_SIZE * sizeof(capnp::word), 0));

    try {

      terminate = disassem(DCR, platform, inWord, msgSize, outWord , outSize);

      if (!terminate) send(client, outWord, outSize * sizeof(capnp::word), 0);
    } catch ( const std::exception& e ) {
      if (verbose) std::cout<<"Error in try decode incoming request: " << e.what() << std::endl;
    }

    close(client);
    memset(inWord, 0, BUFF_SIZE * sizeof(capnp::word));
    memset(outWord, 0, BUFF_SIZE * sizeof(capnp::word));
  }

  close(server);
  BAP_LLVMDisasmDispose(DCR);
  return 0;
}
