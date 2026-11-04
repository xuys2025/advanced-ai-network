#include "pb_internal.h"

// A UDP endpoint may close before its last datagram reaches NETWORK capture.
// Retain BIND ownership (local endpoint and endpoint id), including closed sockets,
// rather than treating every missing live UDP-table row as an unknown process.
// CONNECT metadata can be attributed to an injector after NETWORK reinjection;
// it must not overwrite the process that actually bound the source socket.
typedef struct {
    UINT32 local, remote, pid;
    UINT16 lp, rp;
    UINT64 endpoint;
    ULONGLONG touched;
    BOOL deleted;
    int selected;
} CN_UDP_OWNER;
static CN_UDP_OWNER owners[16384];
static SRWLOCK owner_lock = SRWLOCK_INIT;
static HANDLE flow_handle = INVALID_HANDLE_VALUE, flow_thread = NULL;
static volatile LONG flow_hits = 0, flow_events = 0, selected_hits = 0;
static UINT32 index_for(UINT32 a, UINT16 p, UINT32 b, UINT16 q) { return (a ^ b*2654435761u ^ ((UINT32)p*40503u) ^ ((UINT32)q*97u)) % 16384; }
static BOOL matches(CN_UDP_OWNER *e, UINT32 a, UINT16 p, UINT32 b, UINT16 q) { return e->endpoint && e->local==a && e->lp==p && e->remote==b && e->rp==q; }
static DWORD WINAPI observe(LPVOID ignored) {
    WINDIVERT_ADDRESS addr;
    while (WinDivertRecv(flow_handle,NULL,0,NULL,&addr)) {
        LONG count=InterlockedIncrement(&flow_events);
        if(count<=5)log_message("UDP owner observer: event=%u protocol=%u ipv6=%u pid=%lu",addr.Event,addr.Socket.Protocol,addr.IPv6,addr.Socket.ProcessId);
        if (addr.IPv6 || addr.Flow.Protocol!=IPPROTO_UDP || !addr.Flow.ProcessId) continue;
        if(addr.Event!=WINDIVERT_EVENT_SOCKET_BIND && addr.Event!=WINDIVERT_EVENT_SOCKET_CLOSE)continue;
        UINT32 local6[4],remote6[4],local,remote;
        WinDivertHelperHtonIpv6Address(addr.Flow.LocalAddr,local6);
        WinDivertHelperHtonIpv6Address(addr.Flow.RemoteAddr,remote6);
        memcpy(&local,((BYTE*)local6)+12,4);memcpy(&remote,((BYTE*)remote6)+12,4);
        UINT16 lp=addr.Flow.LocalPort,rp=addr.Flow.RemotePort;
        if(!lp)continue;
        remote=0;rp=0;
        if(count<=3)log_message("UDP flow metadata: event=%u local=%08x:%u remote=%08x:%u pid=%lu",addr.Event,local,lp,remote,rp,addr.Flow.ProcessId);
        int decision=0;
        if(cn_owner_selector && addr.Flow.ProcessId!=g_current_process_id)
            decision=cn_owner_selector(addr.Flow.ProcessId);
        if(decision)log_message("Selected UDP socket event=%u local=%08x:%u remote=%08x:%u pid=%lu decision=%d",addr.Event,local,lp,remote,rp,addr.Flow.ProcessId,decision);
        UINT32 first=index_for(local,lp,remote,rp),chosen=first;
        AcquireSRWLockExclusive(&owner_lock);
        BOOL found=FALSE;
        for(UINT32 i=0;i<8;i++) {
            UINT32 at=(first+i)%16384;
            if(matches(&owners[at],local,lp,remote,rp)){chosen=at;found=TRUE;break;}
            if(!owners[at].endpoint || owners[at].touched<owners[chosen].touched)chosen=at;
        }
        CN_UDP_OWNER *e=&owners[chosen];
        if(addr.Event==WINDIVERT_EVENT_SOCKET_BIND || !found) {
            e->local=local;e->lp=lp;e->remote=remote;e->rp=rp;e->pid=addr.Flow.ProcessId;
            e->endpoint=addr.Flow.EndpointId;e->selected=decision;e->deleted=addr.Event==WINDIVERT_EVENT_SOCKET_CLOSE;e->touched=GetTickCount64();
        } else if(found && e->endpoint==addr.Flow.EndpointId) { e->deleted=TRUE;e->touched=GetTickCount64(); }
        ReleaseSRWLockExclusive(&owner_lock);
    }
    return 0;
}
BOOL cn_udp_owner_start(void) {
    ZeroMemory(owners,sizeof(owners));flow_hits=flow_events=selected_hits=0;
    flow_handle=WinDivertOpen("true",WINDIVERT_LAYER_SOCKET,10,WINDIVERT_FLAG_SNIFF|WINDIVERT_FLAG_RECV_ONLY|WINDIVERT_FLAG_NO_INSTALL);
    if(flow_handle==INVALID_HANDLE_VALUE)return FALSE;
    WinDivertSetParam(flow_handle,WINDIVERT_PARAM_QUEUE_LENGTH,16384);
    flow_thread=CreateThread(NULL,0,observe,NULL,0,NULL);
    if(!flow_thread){WinDivertClose(flow_handle);flow_handle=INVALID_HANDLE_VALUE;return FALSE;}
    return TRUE;
}
void cn_udp_owner_stop(void) {
    if(flow_handle!=INVALID_HANDLE_VALUE){WinDivertShutdown(flow_handle,WINDIVERT_SHUTDOWN_BOTH);WinDivertClose(flow_handle);flow_handle=INVALID_HANDLE_VALUE;}
    if(flow_thread){WaitForSingleObject(flow_thread,3000);CloseHandle(flow_thread);flow_thread=NULL;}
    log_message("UDP ownership: %ld events, %ld closed-endpoint datagrams resolved, %ld selected",flow_events,flow_hits,selected_hits);
}
BOOL cn_udp_owner_alive(void) { DWORD code=0;return flow_thread && GetExitCodeThread(flow_thread,&code) && code==STILL_ACTIVE; }
PROXYBRIDGE_API int AdvancedAINetwork_QueryUdpFlowDecision(UINT32 local,UINT16 lp,UINT32 remote,UINT16 rp,DWORD *pid) {
    for(int retry=0;retry<4;retry++) {
        CN_UDP_OWNER found;ZeroMemory(&found,sizeof(found));
        AcquireSRWLockShared(&owner_lock);
        for(int variant=0;variant<4&&!found.endpoint;variant++) {
            UINT32 a=(variant&2)?0:local,b=(variant&1)?0:remote;UINT16 q=(variant&1)?0:rp;
            UINT32 first=index_for(a,lp,b,q);
            for(UINT32 i=0;i<8;i++){CN_UDP_OWNER *e=&owners[(first+i)%16384];if(matches(e,a,lp,b,q)&&GetTickCount64()-e->touched<30000){found=*e;break;}}
        }
        ReleaseSRWLockShared(&owner_lock);
        if(found.endpoint){*pid=found.pid;InterlockedIncrement(&flow_hits);if(found.selected)InterlockedIncrement(&selected_hits);if(found.selected==2&&cn_owner_selector){int now=cn_owner_selector(found.pid);if(now==1)return 1;}return found.selected;}
        Sleep(1);
    }
    *pid=0;return -1;
}
