using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace AdvancedAINetwork.Gateway {
    // Persistent blocks survive our process. A dynamic WFP session owned by this
    // service supplies soft permits only while the forwarding path is available.
    internal sealed class GatewayFailClosed : IDisposable {
#if GATE_FIXTURE
        static readonly Guid Group = new Guid("2a86976d-9b82-4cdf-9e4b-df0e42920765");
        static readonly string[] RequiredNames = {"ai-outage-fixture.exe"};
        const string Label = "LAN gateway isolated lifetime test";
#else
        static readonly Guid Group = new Guid("ee2ab896-00c5-403a-8009-c382e3214134");
        static readonly string[] RequiredNames = {AiCompatibility.S_11b496da7187c8,"cowork-svc.exe"};
        const string Label = "LAN gateway fail-closed";
#endif
        static readonly Guid Connect4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        static readonly Guid Connect6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        static readonly Guid Application = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        static readonly Guid RemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        const uint Persistent = 1, DynamicSession = 1, Block = 0x1001, Permit = 0x1002;
        const uint ByteBlob = 12, V4Mask = 0x100, Suffix = 11;
        readonly object sync = new object();
        IntPtr lease;
        Spec[] policy;
        string revision;
        bool disposed;

        [StructLayout(LayoutKind.Sequential)] struct Display { public IntPtr name, description; }
        [StructLayout(LayoutKind.Sequential)] struct Blob { public uint size; public IntPtr data; }
        [StructLayout(LayoutKind.Sequential)] struct Value { public uint type; public IntPtr value; }
        [StructLayout(LayoutKind.Sequential)] struct Condition { public Guid key; public uint match; public Value value; }
        [StructLayout(LayoutKind.Sequential)] struct ActionType { public uint type; public Guid key; }
        [StructLayout(LayoutKind.Sequential)] struct Sublayer { public Guid key; public Display display; public uint flags; public IntPtr provider; public Blob data; public ushort weight; }
        [StructLayout(LayoutKind.Sequential)] struct Session { public Guid key; public Display display; public uint flags, timeout, pid; public IntPtr sid, username; public int kernel; }
        [StructLayout(LayoutKind.Explicit,Size=200)] struct Filter {
            [FieldOffset(0)] public Guid key; [FieldOffset(16)] public Display display; [FieldOffset(32)] public uint flags;
            [FieldOffset(64)] public Guid layer; [FieldOffset(80)] public Guid sublayer; [FieldOffset(96)] public Value weight;
            [FieldOffset(112)] public uint count; [FieldOffset(120)] public IntPtr conditions; [FieldOffset(128)] public ActionType action;
        }
        [DllImport("fwpuclnt")] static extern uint FwpmEngineOpen0(IntPtr server,uint authentication,IntPtr identity,IntPtr session,out IntPtr handle);
        [DllImport("fwpuclnt")] static extern uint FwpmEngineClose0(IntPtr handle);
        [DllImport("fwpuclnt")] static extern uint FwpmTransactionBegin0(IntPtr handle,uint flags);
        [DllImport("fwpuclnt")] static extern uint FwpmTransactionCommit0(IntPtr handle);
        [DllImport("fwpuclnt")] static extern uint FwpmTransactionAbort0(IntPtr handle);
        [DllImport("fwpuclnt")] static extern uint FwpmSubLayerAdd0(IntPtr handle,ref Sublayer value,IntPtr security);
        [DllImport("fwpuclnt")] static extern uint FwpmSubLayerGetByKey0(IntPtr handle,ref Guid key,out IntPtr value);
        [DllImport("fwpuclnt")] static extern uint FwpmSubLayerDeleteByKey0(IntPtr handle,ref Guid key);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterAdd0(IntPtr handle,ref Filter filter,IntPtr security,out ulong id);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterGetByKey0(IntPtr handle,ref Guid key,out IntPtr value);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterDeleteByKey0(IntPtr handle,ref Guid key);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterCreateEnumHandle0(IntPtr handle,IntPtr template,out IntPtr iterator);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterEnum0(IntPtr handle,IntPtr iterator,uint wanted,out IntPtr entries,out uint found);
        [DllImport("fwpuclnt")] static extern uint FwpmFilterDestroyEnumHandle0(IntPtr handle,IntPtr iterator);
        [DllImport("fwpuclnt")] static extern void FwpmFreeMemory0(ref IntPtr memory);

        sealed class Memory : IDisposable {
            readonly List<IntPtr> allocations = new List<IntPtr>();
            internal IntPtr Allocate(int bytes) { var p=Marshal.AllocHGlobal(bytes); allocations.Add(p); return p; }
            internal IntPtr Structure<T>(T value) where T:struct {var p=Allocate(Marshal.SizeOf(typeof(T)));Marshal.StructureToPtr(value,p,false);return p;}
            internal IntPtr String(string value) {var p=Marshal.StringToHGlobalUni(value);allocations.Add(p);return p;}
            public void Dispose(){foreach(var p in allocations)Marshal.FreeHGlobal(p);}
        }
        sealed class Spec {
            internal Guid layer;
            internal string name, network;
            internal Guid Key(bool permit) {
                string text=Group+"|"+layer+"|"+(name??network)+"|"+permit;
                using(var sha=SHA256.Create())return new Guid(sha.ComputeHash(Encoding.UTF8.GetBytes(text)).Take(16).ToArray());
            }
            internal Condition Match(Memory memory) {
                if(name!=null) {
                    string tail="\\"+name;
                    var blob=new Blob{size=(uint)((tail.Length+1)*2),data=memory.String(tail)};
                    return new Condition{key=Application,match=Suffix,value=new Value{type=ByteBlob,value=memory.Structure(blob)}};
                }
                string[] pair=network.Split('/');
                byte[] ip=IPAddress.Parse(pair[0]).GetAddressBytes();
                uint address=((uint)ip[0]<<24)|((uint)ip[1]<<16)|((uint)ip[2]<<8)|ip[3];
                var mask=memory.Allocate(8);
                Marshal.WriteInt32(mask,unchecked((int)address));
                Marshal.WriteInt32(mask,4,unchecked((int)(uint.MaxValue<<(32-int.Parse(pair[1])))));
                return new Condition{key=RemoteAddress,value=new Value{type=V4Mask,value=mask}};
            }
        }
        static void Check(uint code,string operation){if(code!=0)throw new IOException(operation+" (WFP 0x"+code.ToString("X8")+")");}
        static IntPtr Open(bool dynamicSession) {
            if(IntPtr.Size!=8||Marshal.SizeOf(typeof(Condition))!=40)throw new PlatformNotSupportedException("WFP guard requires Windows x64.");
            using(var m=new Memory()) {
                var s=new Session{flags=dynamicSession?DynamicSession:0,timeout=5000};
                IntPtr engine;Check(FwpmEngineOpen0(IntPtr.Zero,10,IntPtr.Zero,m.Structure(s),out engine),"Open policy session");return engine;
            }
        }
        static void Transaction(IntPtr engine,Action body) {
            Check(FwpmTransactionBegin0(engine,0),"Begin policy update");
            try{body();Check(FwpmTransactionCommit0(engine),"Commit policy update");}
            catch{FwpmTransactionAbort0(engine);throw;}
        }
        static void EnsureGroup(IntPtr engine) {
            Guid key=Group; IntPtr result;
            uint rc=FwpmSubLayerGetByKey0(engine,ref key,out result);
            if(rc==0) {
                try{var sub=(Sublayer)Marshal.PtrToStructure(result,typeof(Sublayer));if(sub.flags!=Persistent||Marshal.PtrToStringUni(sub.display.name)!=Label)throw new IOException("Unexpected WFP sublayer owner.");}
                finally{FwpmFreeMemory0(ref result);}return;
            }
            if(rc!=0x80320007)Check(rc,"Read policy group");
            using(var m=new Memory()) {
                var sub=new Sublayer{key=Group,flags=Persistent,display=new Display{name=m.String(Label)},weight=0x7100};
                Check(FwpmSubLayerAdd0(engine,ref sub,IntPtr.Zero),"Install persistent policy group");
            }
        }
        static void Add(IntPtr engine,Spec spec,bool permit) {
            using(var m=new Memory()) {
                var f=new Filter{key=spec.Key(permit),display=new Display{name=m.String(Label)},flags=permit?0:Persistent,
                    layer=spec.layer,sublayer=Group,weight=new Value{type=1,value=new IntPtr(permit?12:4)},
                    count=1,conditions=m.Structure(spec.Match(m)),action=new ActionType{type=permit?Permit:Block}};
                ulong id;Check(FwpmFilterAdd0(engine,ref f,IntPtr.Zero,out id),"Add "+(permit?"live permit":"persistent block")+" for "+(spec.name??spec.network));
            }
        }
        static List<Guid> OwnedBlocks(IntPtr engine) {
            var keys=new List<Guid>();IntPtr it;
            Check(FwpmFilterCreateEnumHandle0(engine,IntPtr.Zero,out it),"Enumerate policy");
            try{uint count;do{IntPtr entries;Check(FwpmFilterEnum0(engine,it,256,out entries,out count),"Read policy");
                try{for(int i=0;i<count;i++){
                    var f=(Filter)Marshal.PtrToStructure(Marshal.ReadIntPtr(entries,i*IntPtr.Size),typeof(Filter));
                    if(f.sublayer==Group && f.action.type==Block && (f.flags&Persistent)!=0 && Marshal.PtrToStringUni(f.display.name)==Label)keys.Add(f.key);
                }}finally{if(entries!=IntPtr.Zero)FwpmFreeMemory0(ref entries);}
            }while(count==256);}finally{FwpmFilterDestroyEnumHandle0(engine,it);}return keys;
        }
        static Spec[] Specifications(ManagedRules rules) {
            var names=rules.processes.Concat(RequiredNames).Select(n=>n.ToLowerInvariant()).Select(n=>n.EndsWith(".exe")?n:n+".exe").Distinct();
            return names.SelectMany(n=>new[]{new Spec{layer=Connect4,name=n},new Spec{layer=Connect6,name=n}})
                .Concat(rules.ipv4.Concat(rules.announced).Distinct().Select(n=>new Spec{layer=Connect4,network=n})).ToArray();
        }
        internal static int Audit(ManagedRules rules) {
            int count=0;var engine=Open(false);
            try{foreach(var spec in Specifications(rules)){
                Guid key=spec.Key(false);IntPtr record;Check(FwpmFilterGetByKey0(engine,ref key,out record),"Read persistent block");
                try{var f=(Filter)Marshal.PtrToStructure(record,typeof(Filter));
                    if(f.layer!=spec.layer||f.sublayer!=Group||f.action.type!=Block||(f.flags&0x21)!=Persistent||f.count!=1)throw new IOException("Unexpected persistent filter.");
                    var actual=(Condition)Marshal.PtrToStructure(f.conditions,typeof(Condition));
                    using(var m=new Memory()){
                        var expected=spec.Match(m);
                        if(actual.key!=expected.key||actual.match!=expected.match||actual.value.type!=expected.value.type)throw new IOException("Unexpected filter condition.");
                        if(spec.name!=null){
                            var blob=(Blob)Marshal.PtrToStructure(actual.value.value,typeof(Blob));
                            var wanted=(Blob)Marshal.PtrToStructure(expected.value.value,typeof(Blob));
                            if(blob.size!=wanted.size||Marshal.PtrToStringUni(blob.data)!=("\\"+spec.name))throw new IOException("Unexpected application filter.");
                        }else if(Marshal.ReadInt64(actual.value.value)!=Marshal.ReadInt64(expected.value.value))throw new IOException("Unexpected network filter.");
                    }
                    count++;
                }finally{FwpmFreeMemory0(ref record);}
            }}finally{FwpmEngineClose0(engine);}return count;
        }
        internal void SetPolicy(ManagedRules rules) {
            var specs=Specifications(rules);
            lock(sync) {
                if(disposed)throw new ObjectDisposedException("GatewayFailClosed");
                if(revision==rules.revision)return;
                CloseLease();IntPtr engine=Open(false);
                try{Transaction(engine,delegate{
                    EnsureGroup(engine);
                    // Replace only our own blocks atomically, also repairing any damaged entries.
                    foreach(var k in OwnedBlocks(engine)){var key=k;Check(FwpmFilterDeleteByKey0(engine,ref key),"Replace prior block");}
                    foreach(var spec in specs)Add(engine,spec,false);
                });}finally{FwpmEngineClose0(engine);}
                policy=specs; revision=rules.revision;
            }
        }
        void CloseLease(){if(lease!=IntPtr.Zero){Check(FwpmEngineClose0(lease),"Revoke live permits");lease=IntPtr.Zero;}}
        internal void Pause(){lock(sync){CloseLease();}}
        internal void SetLive(bool live,ManagedRules current) {
            lock(sync){
                if(!live || disposed || current.revision!=revision){CloseLease();return;}
                if(lease!=IntPtr.Zero)return;
                var engine=Open(true);
                try{Transaction(engine,delegate{foreach(var s in policy)if(s.layer==Connect4)Add(engine,s,true);});lease=engine;}
                catch{FwpmEngineClose0(engine);throw;}
            }
        }
        internal bool Live {get{lock(sync){return lease!=IntPtr.Zero;}}}
        internal static void Uninstall() {
            var engine=Open(false);
            try{Transaction(engine,delegate{
                Guid group=Group;IntPtr memory;
                uint rc=FwpmSubLayerGetByKey0(engine,ref group,out memory);
                if(rc==0x80320007)return;
                Check(rc,"Read installed guard");
                try{if(Marshal.PtrToStringUni(((Sublayer)Marshal.PtrToStructure(memory,typeof(Sublayer))).display.name)!=Label)throw new IOException("Unexpected policy group.");}
                finally{FwpmFreeMemory0(ref memory);}
                foreach(var item in OwnedBlocks(engine)){Guid key=item;Check(FwpmFilterDeleteByKey0(engine,ref key),"Remove owned block");}
                Check(FwpmSubLayerDeleteByKey0(engine,ref group),"Remove owned policy group");
            });}finally{FwpmEngineClose0(engine);}
        }
        public void Dispose(){lock(sync){disposed=true;CloseLease();}}
    }
}
