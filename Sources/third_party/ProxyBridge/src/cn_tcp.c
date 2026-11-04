#include "pb_internal.h"

// AdvancedAINetwork: full IPv4 tuple tracking. Assign an independent NAT tag to each
// selected connection, so two sockets reusing a source port cannot share state.
typedef struct CN_TCP_FLOW {
    UINT32 local_ip, remote_ip, relay_ip, syn_sequence;
    UINT16 local_port, remote_port, tag;
    DWORD pid;
    UINT32 ifidx, subifidx;
    BOOL direct, closing;
    ULONGLONG touched;
    struct CN_TCP_FLOW *next;
} CN_TCP_FLOW;
static CN_TCP_FLOW *cn_buckets[4096];
static CN_TCP_FLOW *cn_tags[65536];
static UINT16 cn_next_tag = 10000;
static UINT32 cn_size = 0;

static UINT32 bucket(UINT32 a, UINT32 b, UINT16 p, UINT16 q)
{
    return (a ^ (b * 2654435761u) ^ ((UINT32)p << 16) ^ q) % 4096;
}

static DWORD owner(UINT32 a, UINT16 p, UINT32 b, UINT16 q)
{
    // This runs on the single packet thread. Match all four endpoint fields;
    // source-port-only process caches are ambiguous under Windows port reuse.
    DWORD bytes = 0;
    for (int retry = 0; retry < 4; retry++) {
        DWORD rc = GetExtendedTcpTable(NULL, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (rc != ERROR_INSUFFICIENT_BUFFER && rc != NO_ERROR) return 0;
        bytes += 4096;
        MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)malloc(bytes);
        if (!table) return 0;
        rc = GetExtendedTcpTable(table, &bytes, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        DWORD pid = 0;
        if (rc == NO_ERROR) for (DWORD i=0;i<table->dwNumEntries;i++) {
            MIB_TCPROW_OWNER_PID *r=&table->table[i];
            if (r->dwLocalAddr==a && ntohs((UINT16)r->dwLocalPort)==p &&
                r->dwRemoteAddr==b && ntohs((UINT16)r->dwRemotePort)==q && r->dwOwningPid) {
                pid=r->dwOwningPid;break;
            }
        }
        free(table);
        if (pid) return pid;
        Sleep(1);
    }
    return 0;
}

void cn_tcp_reset(void)
{
    for (int b=0;b<4096;b++) {
        CN_TCP_FLOW *f=cn_buckets[b];
        while (f) {CN_TCP_FLOW *next=f->next;free(f);f=next;}
        cn_buckets[b]=NULL;
    }
    ZeroMemory(cn_tags,sizeof(cn_tags));cn_size=0;
    // Do not restart at tag 10001: Windows can retain the previous service's
    // translated tuple in TIME_WAIT after its process has exited.
    cn_next_tag=(UINT16)(10000+(GetTickCount64()+GetCurrentProcessId()*997u)%50000);
}

static void sweep(void)
{
    ULONGLONG now=GetTickCount64();
    for (int b=0;b<4096;b++) {
        CN_TCP_FLOW **p=&cn_buckets[b];
        while (*p) {
            CN_TCP_FLOW *f=*p;
            if (now-f->touched>(f->closing?30000:1800000)) {
                *p=f->next;if(f->tag){cn_tags[f->tag]=NULL;remove_connection(f->tag,FALSE,FALSE);}free(f);cn_size--;
            } else p=&f->next;
        }
    }
}

BOOL cn_tcp_packet(BYTE *packet, UINT length, WINDIVERT_ADDRESS *addr, WINDIVERT_IPHDR *ip, WINDIVERT_TCPHDR *tcp)
{
    if (!addr->Outbound) {WinDivertSend(windivert_handle,packet,length,NULL,addr);return TRUE;}
    UINT16 sp=ntohs(tcp->SrcPort), dp=ntohs(tcp->DstPort);
    CN_TCP_FLOW *f=NULL;
    // The local relay replies to the NAT tag, not the application's original port.
    if (sp==g_local_relay_port) {
        f=cn_tags[dp];
        if (f && ip->SrcAddr==f->relay_ip && ip->DstAddr==f->remote_ip) {
            ip->SrcAddr=f->remote_ip;ip->DstAddr=f->local_ip;
            tcp->SrcPort=htons(f->remote_port);tcp->DstPort=htons(f->local_port);
            addr->Outbound=((f->local_ip&255)==127 && (f->remote_ip&255)==127);
            addr->Network.IfIdx=f->ifidx;addr->Network.SubIfIdx=f->subifidx;
            f->touched=GetTickCount64();
            WinDivertHelperCalcChecksums(packet,length,addr,0);
            WinDivertSend(windivert_handle,packet,length,NULL,addr);return TRUE;
        }
    }
    UINT32 hash=bucket(ip->SrcAddr,ip->DstAddr,sp,dp);
    CN_TCP_FLOW **slot=&cn_buckets[hash];
    while (*slot) {
        f=*slot;
        if (f->local_ip==ip->SrcAddr && f->remote_ip==ip->DstAddr && f->local_port==sp && f->remote_port==dp) break;
        slot=&f->next;
    }
    f=*slot;
    if (f && tcp->Syn && !tcp->Ack && tcp->SeqNum!=f->syn_sequence) {
        *slot=f->next;if(f->tag){cn_tags[f->tag]=NULL;remove_connection(f->tag,FALSE,FALSE);}free(f);cn_size--;f=NULL;
    }
    if (!f) {
        DWORD pid=owner(ip->SrcAddr,sp,ip->DstAddr,dp);
        if (!pid) {
            // An unclassified initiating SYN must wait for ownership. Replies
            // from listeners and teardown packets can outlive their table row.
            // Existing selected flows were already matched above.
            if (!tcp->Syn || tcp->Ack) WinDivertSend(windivert_handle,packet,length,NULL,addr);
            return TRUE;
        }
        UINT32 config=0;RuleAction action=RULE_ACTION_DIRECT;
        if(pid!=g_current_process_id){
            int selected=cn_owner_selector?cn_owner_selector(pid):0;
            if(selected==2)return TRUE;
            if(selected==1){action=RULE_ACTION_PROXY;config=cn_selected_proxy;g_tl_rule_localhost=((ip->DstAddr&255)==127 && dp==cn_front_port);g_tl_rule_id=0;}
            else {char image[MAX_PROCESS_NAME];if(!get_process_name_from_pid(pid,image,sizeof(image)))return TRUE;action=match_rule(image,ip->DstAddr,dp,FALSE,&config);}
        }
        if(action==RULE_ACTION_PROXY && !g_tl_rule_localhost && (ip->DstAddr&255)==127)action=RULE_ACTION_DIRECT;
        if(action==RULE_ACTION_DIRECT){
            if(cn_size>=4096)sweep();
            if(cn_size<4096){
                CN_TCP_FLOW *d=(CN_TCP_FLOW *)calloc(1,sizeof(*d));
                if(d){d->local_ip=ip->SrcAddr;d->remote_ip=ip->DstAddr;d->local_port=sp;d->remote_port=dp;d->syn_sequence=tcp->SeqNum;d->pid=pid;d->direct=TRUE;d->touched=GetTickCount64();d->next=cn_buckets[hash];cn_buckets[hash]=d;cn_size++;}
            }
            WinDivertSend(windivert_handle,packet,length,NULL,addr);return TRUE;
        }
        if(action!=RULE_ACTION_PROXY)return TRUE;
        // A selected connection established before capture cannot be reconstructed
        // safely; drop its packets and let the application establish a fresh flow.
        if(!tcp->Syn || tcp->Ack)return TRUE;
        PROXY_CONFIG *proxy=find_proxy_config(config);if(!proxy||!proxy->port||!proxy->host[0])return TRUE;
        if(cn_size>=4096){sweep();if(cn_size>=4096)return TRUE;}
        UINT16 tag=0;
        for(int i=0;i<55000;i++) {
            if(++cn_next_tag<10000)cn_next_tag=10000;
            if(cn_next_tag!=g_local_relay_port && !cn_tags[cn_next_tag]){tag=cn_next_tag;break;}
        }
        if(!tag)return TRUE;
        f=(CN_TCP_FLOW *)calloc(1,sizeof(*f));if(!f)return TRUE;
        f->local_ip=ip->SrcAddr;f->remote_ip=ip->DstAddr;f->local_port=sp;f->remote_port=dp;
        // Windows does not accept a packet with a 127/8 source arriving on a TUN.
        // Keep the redirected system-proxy connection entirely on loopback.
        f->relay_ip=(f->remote_ip&255)==127?htonl(INADDR_LOOPBACK):(cn_relay_ip?cn_relay_ip:f->local_ip);
        f->ifidx=addr->Network.IfIdx;f->subifidx=addr->Network.SubIfIdx;
        f->syn_sequence=tcp->SeqNum;f->pid=pid;f->tag=tag;f->next=cn_buckets[hash];cn_buckets[hash]=f;cn_tags[tag]=f;cn_size++;
        add_connection(tag,FALSE,f->local_ip,f->remote_ip,dp,config,pid,g_tl_rule_id);
    }
    f->touched=GetTickCount64();
    if(tcp->Fin||tcp->Rst)f->closing=TRUE;
    if(f->direct){WinDivertSend(windivert_handle,packet,length,NULL,addr);return TRUE;}
    ip->SrcAddr=f->remote_ip;ip->DstAddr=f->relay_ip;
    tcp->SrcPort=htons(f->tag);tcp->DstPort=htons(g_local_relay_port);
    addr->Outbound=((f->relay_ip&255)==127 && (f->remote_ip&255)==127);
    if(cn_relay_ifidx && !addr->Outbound){addr->Network.IfIdx=cn_relay_ifidx;addr->Network.SubIfIdx=0;}
    WinDivertHelperCalcChecksums(packet,length,addr,0);
    WinDivertSend(windivert_handle,packet,length,NULL,addr);return TRUE;
}
