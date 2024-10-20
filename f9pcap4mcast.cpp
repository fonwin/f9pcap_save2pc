/// \file f9pcap4mcast.cpp
/// \author fonwinz@gmail.com
#include "fon9/io/SimpleManager.hpp"
#include "fon9/CtrlBreakHandler.h"
#include "fon9/ConsoleIO.h"
#include "fon9/Endian.hpp"
#include "fon9/File.hpp"
#include "fon9/DefaultThreadPool.hpp"
#include "fon9/CmdArgs.hpp"
#include <set>
#include <inttypes.h>
//--------------------------------------------------------------------------//
#ifdef fon9_WINDOWS
   #include "fon9/io/win/IocpDgram.hpp"
   #pragma comment(lib, "ws2_32.lib")
   namespace fon9 { namespace io {
   class IocpSocketRecvFrom : public IocpDgramImpl {
      fon9_NON_COPY_NON_MOVE(IocpSocketRecvFrom);
      using base = IocpDgramImpl;
      SocketAddress  RecvFromAddr_;
      int            RecvFromAddrLen_;
      char           Padding____[4];
   protected:
      void OnIocpSocket_Received(DcQueueList& rxbuf) override;
   public:
      using OwnerDevice = DgramT<IocpServiceSP, IocpSocketRecvFrom>;
      IocpSocketRecvFrom(OwnerDevice* owner, Socket&& so, SocketResult& soRes)
         : base(reinterpret_cast<base::OwnerDevice*>(owner), std::move(so), soRes) {
      }
      const SocketAddress& GetRecvFromAddr() const {
         return this->RecvFromAddr_;
      }
      void StartRecv(RecvBufferSize preallocSize);
      void ContinueRecv(RecvBufferSize expectSize) {
         this->StartRecv(expectSize);
      }
      struct IocpRecvAux : public base::IocpRecvAux {
         static void ContinueRecv(RecvBuffer& rbuf, RecvBufferSize expectSize, bool isEnableReadable) {
            (void)isEnableReadable;
            IocpSocket& rbase = ContainerOf(rbuf, &IocpSocket::RecvBuffer_);
            static_cast<IocpSocketRecvFrom*>(&rbase)->ContinueRecv(expectSize);
         }
         static SendDirectResult SendDirect(RecvDirectArgs& e, BufferList&& txbuf) {
            // 不支援傳送.
            (void)e; (void)txbuf;
            return SendDirectResult::SendError;
         }
      };
   };
   using IocpDgramRecvFromBase = DeviceImpl_DeviceStartSend<IocpSocketRecvFrom::OwnerDevice, IocpSocketRecvFrom>;

   class IocpDgramRecvFrom : public IocpDgramRecvFromBase {
      fon9_NON_COPY_NON_MOVE(IocpDgramRecvFrom);
      using base = IocpDgramRecvFromBase;
   public:
      using base::base;
      const SocketAddress& GetRecvFromAddr() const {
         return this->ImplSP_->GetRecvFromAddr();
      }
   };
   //--------------------------------------------------------------------------//
   void IocpSocketRecvFrom::OnIocpSocket_Received(DcQueueList& rxbuf) {
      if (fon9_LIKELY(this->State_ >= State::Connecting)) {
         struct RecvAux : public IocpRecvAux {
            static bool IsRecvBufferAlive(Device& dev, RecvBuffer& rbuf) {
               return OwnerDevice::OpImpl_IsRecvBufferAlive(*static_cast<OwnerDevice*>(&dev), rbuf);
            }
         };
         RecvAux aux;
         DeviceRecvBufferReady(*this->Owner_, rxbuf, aux);
      }
      else {
         rxbuf.PopConsumedAll();
      }
   }
   void IocpSocketRecvFrom::StartRecv(RecvBufferSize expectSize) {
      WSABUF bufv[2];
      size_t bufCount;
      if (fon9_UNLIKELY(expectSize < RecvBufferSize::Default)) {
         // 不理會資料事件: Session預期不會有資料.
         // RecvBufferSize::NoRecvEvent, CloseRecv; //還是需要使用[接收事件]偵測斷線.
         bufv[0].len = 0;
         bufv[0].buf = nullptr;
         bufCount = 1;
      }
      else {
         if (expectSize == RecvBufferSize::Default) // 接收緩衝區預設大小.
            expectSize = static_cast<RecvBufferSize>(1024 * 4);
         const size_t allocSize = static_cast<size_t>(expectSize);
         bufCount = this->RecvBuffer_.GetRecvBlockVector(bufv, allocSize >= 64 ? allocSize : (allocSize * 2));
      }
      // 啟動 WSARecv();
      DWORD rxBytes, flags = 0;
      ZeroStruct(this->RecvOverlapped_);
      this->IocpSocketAddRef();
      this->RecvFromAddrLen_ = sizeof(this->RecvFromAddr_.Addr_);
      if (WSARecvFrom(this->Socket_.GetSocketHandle(), bufv, static_cast<DWORD>(bufCount), &rxBytes, &flags,
                      &this->RecvFromAddr_.Addr_, &this->RecvFromAddrLen_,
                      &this->RecvOverlapped_, nullptr) == SOCKET_ERROR) {
         switch (int eno = WSAGetLastError()) {
         case WSA_IO_PENDING: // ERROR_IO_PENDING: 正常接收等候中.
            break;
         case WSAEINVAL: // dgram + NoRecvEvent: 本來就預計不會有 Recv 事件.
            if (expectSize == RecvBufferSize::NoRecvEvent) {
               this->IocpSocketReleaseRef();
               return;
            }
         default: // 接收失敗, 不會產生 OnIocp_* 事件
            this->RecvBuffer_.Clear();
            this->OnIocp_Error(&this->RecvOverlapped_, static_cast<DWORD>(eno));
         }
      }
      else {
         // 已收到(或已從RCVBUF複製進來), 但仍會觸發 OnIocp_Done() 事件,
         // 所以一律在 OnIocp_Done() 事件裡面處理即可.
      }
   }
   } } // namespaces

   using RecvDevice = fon9::io::IocpDgramRecvFrom;
   using IoService = fon9::io::IocpService;
   using IoServiceSP = fon9::io::IocpServiceSP;
#else
   #include "fon9/io/FdrDgram.hpp"
   #include "fon9/io/FdrServiceEpoll.hpp"
   namespace fon9 { namespace io {
   class FdrSocketRecvFrom : public FdrDgramImpl {
      fon9_NON_COPY_NON_MOVE(FdrSocketRecvFrom);
      using base = FdrDgramImpl;
      SocketAddress  RecvFromAddr_;
      socklen_t      RecvFromAddrLen_;
      char           Padding____[8-sizeof(socklen_t)];
   protected:
      void OnFdrEvent_Handling(FdrEventFlag evs) override;
   public:
      using OwnerDevice = DgramT<FdrServiceSP, FdrSocketRecvFrom>;
      FdrSocketRecvFrom(OwnerDevice* owner, Socket&& so, SocketResult& soRes)
         : base(reinterpret_cast<base::OwnerDevice*>(owner), std::move(so), soRes) {
      }
      const SocketAddress& GetRecvFromAddr() const {
         return this->RecvFromAddr_;
      }
      bool CheckRead(Device& dev, bool (*fnIsRecvBufferAlive)(Device& dev, RecvBuffer& rbuf));
   };
   using FdrDgramRecvFromBase = DeviceImpl_DeviceStartSend<FdrSocketRecvFrom::OwnerDevice, FdrSocketRecvFrom>;

   class FdrDgramRecvFrom : public FdrDgramRecvFromBase {
      fon9_NON_COPY_NON_MOVE(FdrDgramRecvFrom);
      using base = FdrDgramRecvFromBase;
   public:
      using base::base;
      const SocketAddress& GetRecvFromAddr() const {
         return this->ImplSP_->GetRecvFromAddr();
      }
   };
   //--------------------------------------------------------------------------//
   void FdrSocketRecvFrom::OnFdrEvent_Handling(FdrEventFlag evs) {
      FdrEventProcessor(this, *this->Owner_, evs);
   }
   bool FdrSocketRecvFrom::CheckRead(Device& dev, bool (*fnIsRecvBufferAlive)(Device& dev, RecvBuffer& rbuf)) {
      size_t   totrd = 0;
      if (fon9_LIKELY(this->RecvSize_ >= RecvBufferSize::Default)) {
         for (;;) {
            size_t expectSize = (this->RecvSize_ == RecvBufferSize::Default
                                 ? 1024 * 4
                                 : static_cast<size_t>(this->RecvSize_));
            if (expectSize < 64)
               expectSize = 64;

            struct iovec   bufv[2];
            bufv[1].iov_len = 0;

            size_t   bufCount = this->RecvBuffer_.GetRecvBlockVector(bufv, expectSize);
            (void)bufCount;

            this->RecvFromAddrLen_ = sizeof(this->RecvFromAddr_.Addr_);
            ssize_t  bytesTransfered = recvfrom(this->GetFD(), bufv[0].iov_base, bufv[0].iov_len, 0,
                                                &this->RecvFromAddr_.Addr_, &this->RecvFromAddrLen_);
            if (fon9_LIKELY(bytesTransfered > 0)) {
               DcQueueList&   rxbuf = this->RecvBuffer_.SetDataReceived(bytesTransfered);

               struct RecvAux : public FdrRecvAux {
                  bool (*FnIsRecvBufferAlive_)(Device& dev, RecvBuffer& rbuf);
                  bool IsRecvBufferAlive(Device& dev, RecvBuffer& rbuf) const {
                     return this->FnIsRecvBufferAlive_ == nullptr || this->FnIsRecvBufferAlive_(dev, rbuf);
                  }
               };
               RecvAux aux;
               aux.FnIsRecvBufferAlive_ = fnIsRecvBufferAlive;
               DeviceRecvBufferReady(dev, rxbuf, aux);

               // 實際取出的資料量, 比要求取出的少 => 資料已全部取出, 所以結束 Recv.
               if (fon9_LIKELY(static_cast<size_t>(bytesTransfered) < (bufv[0].iov_len + bufv[1].iov_len)))
                  return true;

               // 避免一次占用太久, 所以先結束.
               if ((totrd += bytesTransfered) > 1024 * 256)
                  return true;

               // 關閉 readable 偵測: 需要到 op thread 處理 Recv 事件, 所以結束 Recv.
               // 再根據 OnDevice_Recv() 事件處理結果, 決定是否重新啟用 readable 偵測.
               if (fon9_UNLIKELY(aux.IsNeedsUpdateFdrEvent_))
                  return true;

               // Session 決定不要再處理 OnDevice_Recv() 事件, 所以拋棄全部已收到的資料.
               if (fon9_UNLIKELY(this->RecvSize_ < RecvBufferSize::Default))
                  goto __DROP_RECV;
            }
            else if (bytesTransfered < 0)
               goto __READ_ERROR;
            else
               break;
      } // for (;;) readv();
   }
      else {
      __DROP_RECV:
         this->RecvBuffer_.Clear();
         char  buf[1024 * 256];
         for (;;) {
            ssize_t  rdsz = read(this->GetFD(), buf, sizeof(buf));
            if (rdsz < 0)
               goto __READ_ERROR;
            if (rdsz == 0)
               break;
            totrd += rdsz;
         }
      }
      if (totrd > 0)
         return true;
      //  read() == 0: disconnect.
      this->SocketError("Recv", 0);
      return false;

   __READ_ERROR:
      if (int eno = ErrorCannotRetry(errno)) {
         this->SocketError("Recv", eno);
         return false;
      }
      return true;
   }
   } } // namespaces

   using RecvDevice = fon9::io::FdrDgramRecvFrom;
   using IoService = fon9::io::FdrServiceEpoll;
   using IoServiceSP = fon9::io::FdrServiceSP;
#endif
//--------------------------------------------------------------------------//
#define kMAX_PK_SIZE    2048
// 格式參考 https://gitlab.com/wireshark/wireshark/-/wikis/Development/LibpcapFileFormat#packet-data
fon9_PACK(1);
struct PcapFileHdr {
   uint32_t magic_number  = 0xa1b23c4d; // nanosecond-resolution;  microsecond-resolution: 0xa1b2c3d4;
   uint16_t version_major = 2;
   uint16_t version_minor = 4;
   int32_t  thiszone      = 0;   // 使用 UtcNow, 沒有調整 localtime.
   uint32_t sigfigs       = 0;
   uint32_t snaplen       = kMAX_PK_SIZE; // max length of captured packets.
   uint32_t network       = 1;   // for ethernet.
};
static const struct PcapFileHdr  kPcapHhdr;
// ----------------------------------------------------
struct PcapFileRecHdr {
   uint32_t ts_sec;     // timestamp seconds
   uint32_t ts_xsec;    // timestamp nanoseconds/microseconds
   uint32_t incl_len;   // number of octets of packet saved in file
   uint32_t orig_len;   // actual length of packet
};
struct PcapFileRec : public PcapFileRecHdr {
   uint8_t  packet_buffer[kMAX_PK_SIZE];
};
using PcapRecPtr = std::unique_ptr<PcapFileRec>;
// ----------------------------------------------------
// 為了避免從不同 port 擷取到的封包時間亂序(例: port0:T0, port1:T1; T0<T1; 但先擷取到了port1的封包),
// 所以在此需針對時間來排序, 並在 OnDevice_CommonTimer() 時, 將 gFlushPcapInterval 之前的封包寫入檔案.
fon9::TimeInterval   gFlushPcapInterval = fon9::TimeInterval_Millisecond(500);
bool operator<(const PcapFileRecHdr& lhs, const PcapFileRecHdr& rhs) {
   return(lhs.ts_sec == rhs.ts_sec
          ? lhs.ts_xsec < rhs.ts_xsec
          : lhs.ts_sec < rhs.ts_sec);
}
bool operator<(const PcapRecPtr& lhs, const PcapRecPtr& rhs) {
   return(*lhs < *rhs);
}
using PcapListImpl = std::multiset<PcapRecPtr>;
using PcapList = fon9::MustLock<PcapListImpl>;
PcapList gPcapList;
// ----------------------------------------------------
typedef struct f9epbc_RxPkHeader {
   uint64_t    TTS_;        // tick time stamp.  \.
   uint32_t    PkBytes_;    //                    | hdr: f9epbc_kRXPK_HEAD_SIZE = 16 bytes.
   uint16_t    PkBadCount_; //                    |
   uint16_t    Padding2b_;  //                  /  封包序號(暫時提供給debug用:gPkSeqNext)
   uint8_t     Payload_[1]; // 實際 Payload_ 的大小 = PkBytes_;

   void AdjustEndian() {
      // 收到的封包: little endian;
      this->TTS_ = fon9::GetLittleEndian<uint64_t>(&this->TTS_);
      this->PkBytes_ = fon9::GetLittleEndian<uint32_t>(&this->PkBytes_);
      this->PkBadCount_ = fon9::GetLittleEndian<uint16_t>(&this->PkBadCount_);
   }
}  f9epbc_RxPkHeader_t;
fon9_PACK_POP;
uint16_t gPkSeqNext;

//--------------------------------------------------------------------------//
using DecDivisorNS = fon9::DecDivisor<uint64_t, 9>;
static const auto kScaleNS = DecDivisorNS::Scale;
static const auto kDivisorNS = DecDivisorNS::Divisor;
static uint64_t      g1stPkTimeStampNS;
static uint64_t      g1stPkTickClkN;
static fon9::File    gPcapOutFile;
static uint64_t      gLastRxNS;
static uint64_t      gLastAppNS;
static bool          gIsCheckLost;
void AppendPcapRec(const PcapFileRec& rec) {
   gLastAppNS = rec.ts_sec * kDivisorNS + rec.ts_xsec;
   gPcapOutFile.Append(&rec, sizeof(rec) - sizeof(rec.packet_buffer) + rec.incl_len);
}
static inline uint64_t CalcPkTimeStampNS(const f9epbc_RxPkHeader& pkHdr) {
   return g1stPkTimeStampNS + ((pkHdr.TTS_ - g1stPkTickClkN) * 64) / 10; // 每個 clk 6.4 ns;
}
static inline fon9::TimeStamp TimeStampFromNS(uint64_t ns) {
   fon9::TimeStamp retval;
   retval.SetOrigValue(fon9::signed_cast(ns / 1000));
   return retval;
}
static inline fon9::TimeStamp GetPkTimeStamp(const f9epbc_RxPkHeader& pkHdr) {
   return TimeStampFromNS(CalcPkTimeStampNS(pkHdr));
}
//--------------------------------------------------------------------------//
class F9pcapDumpSession : public fon9::io::Session {
   fon9_NON_COPY_NON_MOVE(F9pcapDumpSession);
   using base = fon9::io::Session;
   uint64_t PcapCount_{};
   uint64_t RxEvCount_{};
   bool     IsCapPortSrcMAC_;
   char     Padding_____[7];

public:
   F9pcapDumpSession(bool isCapPortSrcMAC) : IsCapPortSrcMAC_{isCapPortSrcMAC} {
   }

   uint64_t PcapCount() const {
      return this->PcapCount_;
   }
   void OnDevice_StateChanged(fon9::io::Device&, const fon9::io::StateChangedArgs& e) override {
      if (e.BeforeState_ == fon9::io::State::LinkReady)
         this->FlushPcapRec();
   }
   fon9::io::RecvBufferSize OnDevice_LinkReady(fon9::io::Device& dev) override {
      dev.CommonTimerRunAfter(gFlushPcapInterval);
      return static_cast<fon9::io::RecvBufferSize>(kMAX_PK_SIZE);
   }
   fon9::io::RecvBufferSize OnDevice_Recv(fon9::io::Device& dev, fon9::DcQueue& rxbuf) override {
      // char strFrom[128];
      // static_cast<RecvDevice*>(&dev)->GetRecvFromAddr().ToAddrPortStr(strFrom);
      // printf("From:%s\n", strFrom);
      ++this->RxEvCount_;
      f9epbc_RxPkHeader  pkHdr;
      static const auto  kPkHdrSize = sizeof(pkHdr) - sizeof(pkHdr.Payload_);
      while (const f9epbc_RxPkHeader* pPkHdr = static_cast<const f9epbc_RxPkHeader*>(rxbuf.Peek(&pkHdr, kPkHdrSize))) {
         pkHdr = *pPkHdr;
         pkHdr.AdjustEndian();
         // ----------
         if (gIsCheckLost) {
            // Windows 很奇怪, 用 Wireshark 抓包, 明明封包沒遺失, 也沒亂序;
            // 但是這裡收到的封包, 就是會有遺失或亂序?!
            // Linux 就沒有此問題!
            uint16_t pkseq = pkHdr.Padding2b_;
            if (fon9_UNLIKELY(pkseq != gPkSeqNext)) {
               // 僅測試用, 所以沒考慮 overflow;
               if (gPkSeqNext < pkseq) {
                  if (g1stPkTimeStampNS) {
                     const auto lostCount = static_cast<uint16_t>(pkseq - gPkSeqNext);
                     fon9::RevBufferList rbuf_{fon9::kLogBlockNodeSize};
                     fon9::RevPutChar(rbuf_, '\n');
                     if (lostCount > 1) {
                        fon9::RevPrint(rbuf_, " - ", gPkSeqNext, " = ", lostCount);
                     }
                     fon9::RevPrint(rbuf_, "Pk Lost|PkTime=", GetPkTimeStamp(pkHdr), "|Lost=", static_cast<uint16_t>(pkseq - 1));
                     fon9::LogWrite(fon9::LogLevel::Debug, std::move(rbuf_));
                  }
                  gPkSeqNext = static_cast<uint16_t>(pkseq + 1);
               }
               else {
                  fon9_LOG_DEBUG("Pk out of order|Expected=", gPkSeqNext, "|Curr=", pkseq);
               }
            }
            else {
               gPkSeqNext = static_cast<uint16_t>(pkseq + 1);
            }
         }
         // ----------
         if (pkHdr.PkBytes_ < 60 || kMAX_PK_SIZE <= pkHdr.PkBytes_) {
            fon9::RevBufferList rbuf{fon9::kLogBlockNodeSize};
            const char* pend = reinterpret_cast<const char*>(pPkHdr) + kPkHdrSize;
            char*       rout = rbuf.AllocPrefix(kPkHdrSize * 3 + 128);
            *--rout = '\n';
            static const char kHEX[] = "0123456789ABCDEF";
            for (size_t L = 0; L < kPkHdrSize; ++L) {
               const auto pch = static_cast<uint8_t>(*--pend);
               *--rout = kHEX[pch & 0x0f];
               *--rout = kHEX[pch >> 4];
               *--rout = ' ';
            }
            *--rout = '|';
            rbuf.SetPrefixUsed(rout);
            fon9::RevPrint(rbuf,
                           "Bad pk size=", pkHdr.PkBytes_,
                           "|RxSize=", rxbuf.CalcSize(),
                           "|At.PcapCount=", this->PcapCount_,
                           "|At.RxEvCount=", this->RxEvCount_,
                           "|At.PkTime=", GetPkTimeStamp(pkHdr));
            fon9::LogWrite(fon9::LogLevel::Error, std::move(rbuf));
            rxbuf.PopConsumed(kPkHdrSize + pkHdr.PkBytes_);
            continue;
         }
         if (rxbuf.CalcSize() < kPkHdrSize + pkHdr.PkBytes_)
            break;
         rxbuf.PopConsumed(kPkHdrSize);
         if (fon9_UNLIKELY(g1stPkTickClkN == 0)) {
            // 首次收到訊息, 需記錄此時的 timestamp, tick clk, 用來計算後續封包的時間;
            g1stPkTickClkN = pkHdr.TTS_;
            g1stPkTimeStampNS = fon9::unsigned_cast(fon9::UtcNow().ShiftUnit<kScaleNS>());
         }
         else if (pkHdr.TTS_ < g1stPkTickClkN) {
            rxbuf.PopConsumed(pkHdr.PkBytes_);
            continue;
         }
         PcapRecPtr  prec{new PcapFileRec};
         uint64_t    ts = gLastRxNS = CalcPkTimeStampNS(pkHdr);
         prec->ts_sec = static_cast<uint32_t>(ts / kDivisorNS);
         prec->ts_xsec = static_cast<uint32_t>(ts % kDivisorNS);
         prec->incl_len = pkHdr.PkBytes_;
         prec->orig_len = prec->incl_len;
         rxbuf.Read(prec->packet_buffer, prec->incl_len);
         if (this->IsCapPortSrcMAC_) {
            uint16_t srcPort = static_cast<RecvDevice*>(&dev)->GetRecvFromAddr().GetPort();
            // 抓包設備 port0 使用 SrcIp:2000 送出; port1 使用 SrcIp:2001 送出; ...之後類推;
            prec->packet_buffer[11] = static_cast<uint8_t>(srcPort - 2000);
         }
         gPcapList.Lock()->insert(std::move(prec));
         ++this->PcapCount_;
      }
      return static_cast<fon9::io::RecvBufferSize>(kMAX_PK_SIZE);
   }
   void FlushPcapRec(PcapList::Locker&& plist) {
      PcapListImpl recs = std::move(*plist);
      plist.unlock();
      for (const PcapRecPtr& prec : recs)
         AppendPcapRec(*prec);
   }
   void FlushPcapRec() {
      this->FlushPcapRec(gPcapList.Lock());
   }
   void OnDevice_CommonTimer(fon9::io::Device& dev, fon9::TimeStamp now) override {
      dev.CommonTimerRunAfter(gFlushPcapInterval);
      uint64_t       bfns = fon9::unsigned_cast((now - gFlushPcapInterval).ShiftUnit<kScaleNS>());
      PcapFileRecHdr flushBf;
      flushBf.ts_sec = static_cast<uint32_t>(bfns / kDivisorNS);
      flushBf.ts_xsec = static_cast<uint32_t>(bfns % kDivisorNS);

      PcapRecPtr prec;
      for (;;) {
         {
            auto plist = gPcapList.Lock();
            if (plist->empty())
               break;
            auto& rec = *plist->begin();
            if (flushBf < *rec)
               return;
            prec.reset(rec.get());
            const_cast<PcapRecPtr*>(&rec)->release();
            plist->erase(plist->begin());
         }
         AppendPcapRec(*prec);
      }
   }
   void PrintInfo(bool isFlush) {
      size_t qcount;
      if (isFlush) {
         qcount = 0;
         this->FlushPcapRec(); // 強制寫入可能造成亂序, 所以要印出 FileSize 資訊嗎?
      }
      else {
         auto plist = gPcapList.Lock();
         if ((qcount = plist->size()) > 0) {
         }
      }
      gPcapOutFile.Sync();
      puts(fon9::RevPrintTo<std::string>(
         // "FileSize=", gPcapOutFile.GetFileSize(),
         "|PcapCount=", this->PcapCount_,
         "|RxEvCount=", this->RxEvCount_,
         "|Queuing=", qcount,
         "|PkLastRx=", TimeStampFromNS(gLastRxNS),
         "|PkLastApp=", TimeStampFromNS(gLastAppNS)
         ).c_str());
   }
};
using F9pcapDumpSessionSP = fon9::intrusive_ptr<F9pcapDumpSession>;

//--------------------------------------------------------------------------//

int main(int argc, const char** argv) {
#if defined(_MSC_VER) && defined(_DEBUG)
   _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

   fon9_SetConsoleUTF8();
   fon9_SetupCtrlBreakHandler();

   if (argc < 4) {
      puts(R"**(
Usage:
   outfile filemode "DeviceConfig" [--CapPortSrcMAC]

   filemode:
      - w = Write
      - a = Append
      - o = OpenAlways
      - c = CreatePath
      - n = MustNew

   --CapPortSrcMAC
     Store [cap device port] to ethernet frame [source MAC address].

   -l seconds
     linger quit seconds.

e.g.
    dumpout.pcap ca "Group=225.6.6.6|Bind=22566"
)**");
      return 3;
   }

   fon9::PresetDefaultThreadPoolValues(1, fon9::TimeInterval{});

   uint32_t       lingerQuitSecs = 0;
   std::string    outfname = argv[1];
   fon9::FileMode fmode = fon9::StrToFileMode(fon9::StrView_cstr(argv[2]));
   const char*    devArgs = argv[3];

   fon9::StrView  argstr;
   // linger quit seconds.
   argstr = fon9::GetCmdArg(argc, argv, "l", nullptr);
   if (!argstr.IsNull()) {
      lingerQuitSecs = fon9::StrTo(argstr, 1u);
   }
   // -L check lost(for debug)
   gIsCheckLost = !fon9::GetCmdArg(argc, argv, "L", nullptr).IsNull();
   const bool isCapPortSrcMAC = !fon9::GetCmdArg(argc, argv, nullptr, "CapPortSrcMAC").IsNull();

   fon9::io::IoServiceArgs iosvArgs;
   fon9::RevBufferList     rbuf{1024};
   fon9::ParseConfig(iosvArgs, "ThreadCount=1", rbuf);
   IoService::MakeResult   err;
   IoServiceSP             iosv = IoService::MakeService(iosvArgs, "IoService", err);
   if (!iosv) {
      puts(fon9::RevPrintTo<std::string>("IoService.MakeService|", err).c_str());
      return 3;
   }

   auto fres = gPcapOutFile.Open(outfname, fmode);
   fon9::StrView ferrFn;
   if (fres.IsError()) {
      ferrFn = "Open";
   __OUTFILE_ERROR:;
      puts(fon9::RevPrintTo<std::string>("outfile=", outfname, "fn=", ferrFn, "|err=", fres).c_str());
      return 3;
   }
   fres = gPcapOutFile.GetFileSize();
   if (fres.IsError()) {
      ferrFn = "GetFileSize";
      goto __OUTFILE_ERROR;
   }
   if (fres.GetResult() == 0) {
      fres = gPcapOutFile.Append(&kPcapHhdr, sizeof(kPcapHhdr));
      if (fres.IsError()) {
         ferrFn = "Write.FileHead";
         goto __OUTFILE_ERROR;
      }
   }

   fon9::io::ManagerCSP mgr{new fon9::io::SimpleManager{}};
   F9pcapDumpSessionSP  ses{new F9pcapDumpSession{isCapPortSrcMAC}};
   fon9::io::DeviceSP   dev{new RecvDevice(iosv, ses, mgr)};

   dev->Initialize();
   dev->AsyncOpen(devArgs);
   dev->WaitGetDeviceId();// 等候 dev->AsyncOpen() 執行完畢.
   std::this_thread::sleep_for(std::chrono::milliseconds{10}); // 等候其他 thread 啟動.

   puts("'?' or 'help' for command list.");
   char cmdbuf[1024];
   while (fon9_AppBreakMsg == nullptr) {
      printf("> ");
      fflush(stdout);
      if (!fgets(cmdbuf, sizeof(cmdbuf), stdin))
         break;
      fon9::StrView  cmd{fon9::StrView_cstr(cmdbuf)};
      fon9::StrTrim(&cmd);
      gPcapOutFile.Sync();
      if (cmd.empty())
         continue;

      if (cmd == "quit")
         break;
      if (cmd == "?" || cmd == "help") {
         puts(R"(
Commands:
   ? or help      this menu.
   quit           quit program.
   log N          N=LogLevel: 4=WARN, 5=ERROR
   p              print info.
   f              force flush.
)");
         continue;
      }
      else if (cmd == "p") {
         ses->PrintInfo(false);
         continue;
      }
      else if (cmd == "f") {
         ses->PrintInfo(true);
         continue;
      }

      fon9::StrView cmdln{cmd};
      fon9::StrView c1 = fon9::StrFetchTrim(cmdln, &fon9::isspace);
      if (c1 == "log") {
         if (!cmdln.empty())
            fon9::LogLevel_ = static_cast<fon9::LogLevel>(fon9::StrTo(cmdln, 0u));
         puts(fon9::RevPrintTo<std::string>("LogLevel=", fon9::GetLevelStr(fon9::LogLevel_)).c_str());
      }
      else if (c1 == "lq") {
         if ((lingerQuitSecs = fon9::StrTo(cmdln, lingerQuitSecs)) <= 0)
            lingerQuitSecs = 1;
         break;
      }
   }
   if (lingerQuitSecs > 0) {
      fon9_AppBreakMsg = nullptr;
      // 由於使用 1G(100M) 接收抓包結果, 所以在瞬間大量測試完畢後, 可能尚未全部收完抓包訊息.
      // 因此在此等候一段時間, 確定沒有任何訊息了, 才結束程式.
      printf("Linger:%u secs\n", lingerQuitSecs);
      uint32_t lcount = 0;
      while (fon9_AppBreakMsg == nullptr) {
         const auto pcount = ses->PcapCount();
         printf("\r" "Linger(%u): %" PRIu64 ". ", lingerQuitSecs - lcount, ses->PcapCount());
         std::this_thread::sleep_for(std::chrono::milliseconds{1000});
         if (pcount == ses->PcapCount()) {
            if (++lcount >= lingerQuitSecs)
               break;
            continue;
         }
         lcount = 0;
      }
      printf("\r%-40s\n", fon9_AppBreakMsg ? fon9_AppBreakMsg : "");
   }
   ses->PrintInfo(true);
   dev->AsyncDispose("quit");
   dev->WaitGetDeviceInfo(); // 等候 dev->AsyncDispose("quit") 執行完畢.
   // wait all AcceptedClient dispose
   while (mgr->use_count() != 2) // mgr(+1), dev->Manager_(+1)
      std::this_thread::yield();
}
