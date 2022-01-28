// cgo -godefs -- -Wall -Werror -static -I/tmp/include /build/unix/linux/types.go | go run mkpost.go
// Code generated by the command above; see README.md. DO NOT EDIT.

//go:build ppc64le && linux
// +build ppc64le,linux

package unix

const (
	SizeofPtr  = 0x8
	SizeofLong = 0x8
)

type (
	_C_long int64
)

type Timespec struct {
	Sec  int64
	Nsec int64
}

type Timeval struct {
	Sec  int64
	Usec int64
}

type Timex struct {
	Modes     uint32
	Offset    int64
	Freq      int64
	Maxerror  int64
	Esterror  int64
	Status    int32
	Constant  int64
	Precision int64
	Tolerance int64
	Time      Timeval
	Tick      int64
	Ppsfreq   int64
	Jitter    int64
	Shift     int32
	Stabil    int64
	Jitcnt    int64
	Calcnt    int64
	Errcnt    int64
	Stbcnt    int64
	Tai       int32
	_         [44]byte
}

type Time_t int64

type Tms struct {
	Utime  int64
	Stime  int64
	Cutime int64
	Cstime int64
}

type Utimbuf struct {
	Actime  int64
	Modtime int64
}

type Rusage struct {
	Utime    Timeval
	Stime    Timeval
	Maxrss   int64
	Ixrss    int64
	Idrss    int64
	Isrss    int64
	Minflt   int64
	Majflt   int64
	Nswap    int64
	Inblock  int64
	Oublock  int64
	Msgsnd   int64
	Msgrcv   int64
	Nsignals int64
	Nvcsw    int64
	Nivcsw   int64
}

type Stat_t struct {
	Dev     uint64
	Ino     uint64
	Nlink   uint64
	Mode    uint32
	Uid     uint32
	Gid     uint32
	_       int32
	Rdev    uint64
	Size    int64
	Blksize int64
	Blocks  int64
	Atim    Timespec
	Mtim    Timespec
	Ctim    Timespec
	_       uint64
	_       uint64
	_       uint64
}

type Dirent struct {
	Ino    uint64
	Off    int64
	Reclen uint16
	Type   uint8
	Name   [256]uint8
	_      [5]byte
}

type Flock_t struct {
	Type   int16
	Whence int16
	Start  int64
	Len    int64
	Pid    int32
	_      [4]byte
}

type DmNameList struct {
	Dev  uint64
	Next uint32
	Name [0]byte
	_    [4]byte
}

const (
	FADV_DONTNEED = 0x4
	FADV_NOREUSE  = 0x5
)

type RawSockaddrNFCLLCP struct {
	Sa_family        uint16
	Dev_idx          uint32
	Target_idx       uint32
	Nfc_protocol     uint32
	Dsap             uint8
	Ssap             uint8
	Service_name     [63]uint8
	Service_name_len uint64
}

type RawSockaddr struct {
	Family uint16
	Data   [14]uint8
}

type RawSockaddrAny struct {
	Addr RawSockaddr
	Pad  [96]uint8
}

type Iovec struct {
	Base *byte
	Len  uint64
}

type Msghdr struct {
	Name       *byte
	Namelen    uint32
	Iov        *Iovec
	Iovlen     uint64
	Control    *byte
	Controllen uint64
	Flags      int32
	_          [4]byte
}

type Cmsghdr struct {
	Len   uint64
	Level int32
	Type  int32
}

type ifreq struct {
	Ifrn [16]byte
	Ifru [24]byte
}

const (
	SizeofSockaddrNFCLLCP = 0x60
	SizeofIovec           = 0x10
	SizeofMsghdr          = 0x38
	SizeofCmsghdr         = 0x10
)

const (
	SizeofSockFprog = 0x10
)

type PtraceRegs struct {
	Gpr       [32]uint64
	Nip       uint64
	Msr       uint64
	Orig_gpr3 uint64
	Ctr       uint64
	Link      uint64
	Xer       uint64
	Ccr       uint64
	Softe     uint64
	Trap      uint64
	Dar       uint64
	Dsisr     uint64
	Result    uint64
}

type FdSet struct {
	Bits [16]int64
}

type Sysinfo_t struct {
	Uptime    int64
	Loads     [3]uint64
	Totalram  uint64
	Freeram   uint64
	Sharedram uint64
	Bufferram uint64
	Totalswap uint64
	Freeswap  uint64
	Procs     uint16
	Pad       uint16
	Totalhigh uint64
	Freehigh  uint64
	Unit      uint32
	_         [0]uint8
	_         [4]byte
}

type Ustat_t struct {
	Tfree  int32
	Tinode uint64
	Fname  [6]uint8
	Fpack  [6]uint8
	_      [4]byte
}

type EpollEvent struct {
	Events uint32
	_      int32
	Fd     int32
	Pad    int32
}

const (
	POLLRDHUP = 0x2000
)

type Sigset_t struct {
	Val [16]uint64
}

const _C__NSIG = 0x41

type Termios struct {
	Iflag  uint32
	Oflag  uint32
	Cflag  uint32
	Lflag  uint32
	Cc     [19]uint8
	Line   uint8
	Ispeed uint32
	Ospeed uint32
}

type Taskstats struct {
	Version                   uint16
	Ac_exitcode               uint32
	Ac_flag                   uint8
	Ac_nice                   uint8
	Cpu_count                 uint64
	Cpu_delay_total           uint64
	Blkio_count               uint64
	Blkio_delay_total         uint64
	Swapin_count              uint64
	Swapin_delay_total        uint64
	Cpu_run_real_total        uint64
	Cpu_run_virtual_total     uint64
	Ac_comm                   [32]uint8
	Ac_sched                  uint8
	Ac_pad                    [3]uint8
	_                         [4]byte
	Ac_uid                    uint32
	Ac_gid                    uint32
	Ac_pid                    uint32
	Ac_ppid                   uint32
	Ac_btime                  uint32
	Ac_etime                  uint64
	Ac_utime                  uint64
	Ac_stime                  uint64
	Ac_minflt                 uint64
	Ac_majflt                 uint64
	Coremem                   uint64
	Virtmem                   uint64
	Hiwater_rss               uint64
	Hiwater_vm                uint64
	Read_char                 uint64
	Write_char                uint64
	Read_syscalls             uint64
	Write_syscalls            uint64
	Read_bytes                uint64
	Write_bytes               uint64
	Cancelled_write_bytes     uint64
	Nvcsw                     uint64
	Nivcsw                    uint64
	Ac_utimescaled            uint64
	Ac_stimescaled            uint64
	Cpu_scaled_run_real_total uint64
	Freepages_count           uint64
	Freepages_delay_total     uint64
	Thrashing_count           uint64
	Thrashing_delay_total     uint64
	Ac_btime64                uint64
}

type cpuMask uint64

const (
	_NCPUBITS = 0x40
)

const (
	CBitFieldMaskBit0  = 0x1
	CBitFieldMaskBit1  = 0x2
	CBitFieldMaskBit2  = 0x4
	CBitFieldMaskBit3  = 0x8
	CBitFieldMaskBit4  = 0x10
	CBitFieldMaskBit5  = 0x20
	CBitFieldMaskBit6  = 0x40
	CBitFieldMaskBit7  = 0x80
	CBitFieldMaskBit8  = 0x100
	CBitFieldMaskBit9  = 0x200
	CBitFieldMaskBit10 = 0x400
	CBitFieldMaskBit11 = 0x800
	CBitFieldMaskBit12 = 0x1000
	CBitFieldMaskBit13 = 0x2000
	CBitFieldMaskBit14 = 0x4000
	CBitFieldMaskBit15 = 0x8000
	CBitFieldMaskBit16 = 0x10000
	CBitFieldMaskBit17 = 0x20000
	CBitFieldMaskBit18 = 0x40000
	CBitFieldMaskBit19 = 0x80000
	CBitFieldMaskBit20 = 0x100000
	CBitFieldMaskBit21 = 0x200000
	CBitFieldMaskBit22 = 0x400000
	CBitFieldMaskBit23 = 0x800000
	CBitFieldMaskBit24 = 0x1000000
	CBitFieldMaskBit25 = 0x2000000
	CBitFieldMaskBit26 = 0x4000000
	CBitFieldMaskBit27 = 0x8000000
	CBitFieldMaskBit28 = 0x10000000
	CBitFieldMaskBit29 = 0x20000000
	CBitFieldMaskBit30 = 0x40000000
	CBitFieldMaskBit31 = 0x80000000
	CBitFieldMaskBit32 = 0x100000000
	CBitFieldMaskBit33 = 0x200000000
	CBitFieldMaskBit34 = 0x400000000
	CBitFieldMaskBit35 = 0x800000000
	CBitFieldMaskBit36 = 0x1000000000
	CBitFieldMaskBit37 = 0x2000000000
	CBitFieldMaskBit38 = 0x4000000000
	CBitFieldMaskBit39 = 0x8000000000
	CBitFieldMaskBit40 = 0x10000000000
	CBitFieldMaskBit41 = 0x20000000000
	CBitFieldMaskBit42 = 0x40000000000
	CBitFieldMaskBit43 = 0x80000000000
	CBitFieldMaskBit44 = 0x100000000000
	CBitFieldMaskBit45 = 0x200000000000
	CBitFieldMaskBit46 = 0x400000000000
	CBitFieldMaskBit47 = 0x800000000000
	CBitFieldMaskBit48 = 0x1000000000000
	CBitFieldMaskBit49 = 0x2000000000000
	CBitFieldMaskBit50 = 0x4000000000000
	CBitFieldMaskBit51 = 0x8000000000000
	CBitFieldMaskBit52 = 0x10000000000000
	CBitFieldMaskBit53 = 0x20000000000000
	CBitFieldMaskBit54 = 0x40000000000000
	CBitFieldMaskBit55 = 0x80000000000000
	CBitFieldMaskBit56 = 0x100000000000000
	CBitFieldMaskBit57 = 0x200000000000000
	CBitFieldMaskBit58 = 0x400000000000000
	CBitFieldMaskBit59 = 0x800000000000000
	CBitFieldMaskBit60 = 0x1000000000000000
	CBitFieldMaskBit61 = 0x2000000000000000
	CBitFieldMaskBit62 = 0x4000000000000000
	CBitFieldMaskBit63 = 0x8000000000000000
)

type SockaddrStorage struct {
	Family uint16
	_      [118]uint8
	_      uint64
}

type HDGeometry struct {
	Heads     uint8
	Sectors   uint8
	Cylinders uint16
	Start     uint64
}

type Statfs_t struct {
	Type    int64
	Bsize   int64
	Blocks  uint64
	Bfree   uint64
	Bavail  uint64
	Files   uint64
	Ffree   uint64
	Fsid    Fsid
	Namelen int64
	Frsize  int64
	Flags   int64
	Spare   [4]int64
}

type TpacketHdr struct {
	Status  uint64
	Len     uint32
	Snaplen uint32
	Mac     uint16
	Net     uint16
	Sec     uint32
	Usec    uint32
	_       [4]byte
}

const (
	SizeofTpacketHdr = 0x20
)

type RTCPLLInfo struct {
	Ctrl    int32
	Value   int32
	Max     int32
	Min     int32
	Posmult int32
	Negmult int32
	Clock   int64
}

type BlkpgPartition struct {
	Start   int64
	Length  int64
	Pno     int32
	Devname [64]uint8
	Volname [64]uint8
	_       [4]byte
}

const (
	BLKPG = 0x20001269
)

type XDPUmemReg struct {
	Addr     uint64
	Len      uint64
	Size     uint32
	Headroom uint32
	Flags    uint32
	_        [4]byte
}

type CryptoUserAlg struct {
	Name        [64]uint8
	Driver_name [64]uint8
	Module_name [64]uint8
	Type        uint32
	Mask        uint32
	Refcnt      uint32
	Flags       uint32
}

type CryptoStatAEAD struct {
	Type         [64]uint8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Err_cnt      uint64
}

type CryptoStatAKCipher struct {
	Type         [64]uint8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Verify_cnt   uint64
	Sign_cnt     uint64
	Err_cnt      uint64
}

type CryptoStatCipher struct {
	Type         [64]uint8
	Encrypt_cnt  uint64
	Encrypt_tlen uint64
	Decrypt_cnt  uint64
	Decrypt_tlen uint64
	Err_cnt      uint64
}

type CryptoStatCompress struct {
	Type            [64]uint8
	Compress_cnt    uint64
	Compress_tlen   uint64
	Decompress_cnt  uint64
	Decompress_tlen uint64
	Err_cnt         uint64
}

type CryptoStatHash struct {
	Type      [64]uint8
	Hash_cnt  uint64
	Hash_tlen uint64
	Err_cnt   uint64
}

type CryptoStatKPP struct {
	Type                      [64]uint8
	Setsecret_cnt             uint64
	Generate_public_key_cnt   uint64
	Compute_shared_secret_cnt uint64
	Err_cnt                   uint64
}

type CryptoStatRNG struct {
	Type          [64]uint8
	Generate_cnt  uint64
	Generate_tlen uint64
	Seed_cnt      uint64
	Err_cnt       uint64
}

type CryptoStatLarval struct {
	Type [64]uint8
}

type CryptoReportLarval struct {
	Type [64]uint8
}

type CryptoReportHash struct {
	Type       [64]uint8
	Blocksize  uint32
	Digestsize uint32
}

type CryptoReportCipher struct {
	Type        [64]uint8
	Blocksize   uint32
	Min_keysize uint32
	Max_keysize uint32
}

type CryptoReportBlkCipher struct {
	Type        [64]uint8
	Geniv       [64]uint8
	Blocksize   uint32
	Min_keysize uint32
	Max_keysize uint32
	Ivsize      uint32
}

type CryptoReportAEAD struct {
	Type        [64]uint8
	Geniv       [64]uint8
	Blocksize   uint32
	Maxauthsize uint32
	Ivsize      uint32
}

type CryptoReportComp struct {
	Type [64]uint8
}

type CryptoReportRNG struct {
	Type     [64]uint8
	Seedsize uint32
}

type CryptoReportAKCipher struct {
	Type [64]uint8
}

type CryptoReportKPP struct {
	Type [64]uint8
}

type CryptoReportAcomp struct {
	Type [64]uint8
}

type LoopInfo struct {
	Number           int32
	Device           uint64
	Inode            uint64
	Rdevice          uint64
	Offset           int32
	Encrypt_type     int32
	Encrypt_key_size int32
	Flags            int32
	Name             [64]uint8
	Encrypt_key      [32]uint8
	Init             [2]uint64
	Reserved         [4]uint8
	_                [4]byte
}

type TIPCSubscr struct {
	Seq     TIPCServiceRange
	Timeout uint32
	Filter  uint32
	Handle  [8]uint8
}

type TIPCSIOCLNReq struct {
	Peer     uint32
	Id       uint32
	Linkname [68]uint8
}

type TIPCSIOCNodeIDReq struct {
	Peer uint32
	Id   [16]uint8
}

type PPSKInfo struct {
	Assert_sequence uint32
	Clear_sequence  uint32
	Assert_tu       PPSKTime
	Clear_tu        PPSKTime
	Current_mode    int32
	_               [4]byte
}

const (
	PPS_GETPARAMS = 0x400870a1
	PPS_SETPARAMS = 0x800870a2
	PPS_GETCAP    = 0x400870a3
	PPS_FETCH     = 0xc00870a4
)

const (
	PIDFD_NONBLOCK = 0x800
)

type SysvIpcPerm struct {
	Key  int32
	Uid  uint32
	Gid  uint32
	Cuid uint32
	Cgid uint32
	Mode uint32
	Seq  uint32
	_    uint32
	_    uint64
	_    uint64
}
type SysvShmDesc struct {
	Perm   SysvIpcPerm
	Atime  int64
	Dtime  int64
	Ctime  int64
	Segsz  uint64
	Cpid   int32
	Lpid   int32
	Nattch uint64
	_      uint64
	_      uint64
}
