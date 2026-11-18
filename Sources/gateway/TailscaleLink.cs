using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace AdvancedAINetwork.Gateway {
    internal interface IExitLink : IDisposable {
        string GatewayMac { get; }
        void Refresh();
        void Send(byte[] packet, int length, byte[] metadata);
    }

    internal sealed class TailscaleLink : IExitLink {
        readonly Process child;
        readonly BlockingCollection<byte[]> queue = new BlockingCollection<byte[]>(256);
        readonly Action<byte[]> receive;
        volatile string state = "waiting", detail = "", loginUrl = "";
        long heartbeat, generation;
        internal long Generation {get{return Interlocked.Read(ref generation);}}
        long verifiedGeneration = -1;
        internal bool Verified { get { return Interlocked.Read(ref verifiedGeneration)==Generation && Ready; } }
        internal void Confirm(long measuredGeneration) {
            Refresh();
            Interlocked.Exchange(ref verifiedGeneration,measuredGeneration);
            if(!Verified)throw new IOException("出口状态已变化，请重新验证。");
        }
        internal bool Exited {get{return child.HasExited;}}
        int closed;
        internal string LoginUrl { get { return loginUrl; } }
        public string GatewayMac { get { return ""; } }
        internal static string ParseNode(string value) {
            IPAddress address;
            if (IPAddress.TryParse(value, out address) && address.ToString() == value) {
                byte[] b = address.GetAddressBytes();
                if (b.Length == 4 && b[0] == 100 && b[1] >= 64 && b[1] < 128) return value;
            }
            throw new IOException("请输入出口节点的 Tailscale IPv4 地址（100.64.0.0/10）。");
        }
        static string StateDirectory(string root, string node) {
            var acl = new DirectorySecurity();
            acl.SetAccessRuleProtection(true, false);
            foreach (var sid in new[]{WellKnownSidType.LocalSystemSid, WellKnownSidType.BuiltinAdministratorsSid})
                acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid,null),FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
            var dir = Directory.CreateDirectory(Path.Combine(root, "tailscale-identities"), acl);
            return Directory.CreateDirectory(Path.Combine(dir.FullName, node), acl).FullName;
        }
        internal TailscaleLink(string root, string target, IPAddress local, Action<byte[]> receive) {
            this.receive = receive;
            string node = ParseNode(target);
            string exe = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "TailscaleExit.exe");
            if (!File.Exists(exe)) throw new IOException("此版本缺少 Tailscale 出口组件。");
            var start = new ProcessStartInfo(exe, "\"" + StateDirectory(root,node) + "\" " + node + " " + local + " " + Process.GetCurrentProcess().Id) {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardInput = true,
                RedirectStandardOutput = true, RedirectStandardError = true, StandardErrorEncoding=System.Text.Encoding.UTF8
            };
            start.EnvironmentVariables["TS_NO_LOGS_NO_SUPPORT"]="true";
            child = new Process { StartInfo = start };
            child.ErrorDataReceived += (sender, e) => UpdateState(e.Data);
            child.Start();
            try {
                child.BeginErrorReadLine();
                Task.Factory.StartNew(WritePackets, TaskCreationOptions.LongRunning);
                Task.Factory.StartNew(ReadPackets, TaskCreationOptions.LongRunning);
            } catch { Dispose(); throw; }
        }
        void UpdateState(string line) {
            if (line == null || line.Length > 4096 || !line.StartsWith("{")) return;
            try {
                var msg = new JavaScriptSerializer().Deserialize<Dictionary<string,string>>(line);
                string next = msg["state"], value;
                msg.TryGetValue("detail",out value);
                Uri uri;
                loginUrl = next=="login" && Uri.TryCreate(value,UriKind.Absolute,out uri) && uri.Scheme=="https"
                    && uri.IsDefaultPort && uri.Host=="login.tailscale.com" && uri.UserInfo=="" ? uri.AbsoluteUri : "";
                detail = next=="error" || next=="offline" ? value : "";
                if(next!="ready" || DateTime.UtcNow.Ticks-Interlocked.Read(ref heartbeat)>=8*TimeSpan.TicksPerSecond){
                    Interlocked.Increment(ref generation);
                }
                Interlocked.Exchange(ref heartbeat, DateTime.UtcNow.Ticks);
                state = next;
            } catch (Exception) { }
        }
        bool Ready { get { return state=="ready" && Volatile.Read(ref closed)==0 &&
            DateTime.UtcNow.Ticks - Interlocked.Read(ref heartbeat) < 8*TimeSpan.TicksPerSecond; } }
        internal void WaitReady(WaitHandle stopping) {
            var timeout=Stopwatch.StartNew();
            while (!Ready) {
                if (child.HasExited || state=="error" || state=="offline" || timeout.Elapsed.TotalMinutes>=3) Refresh();
                if (stopping.WaitOne(150)) throw new OperationCanceledException();
            }
        }
        public void Refresh() {
            if (!Ready || Exited) throw new IOException(string.IsNullOrEmpty(detail) ? "Tailscale 出口节点尚未就绪，请核对登录状态、节点授权与连接。" : detail);
        }
        public void Send(byte[] packet,int length,byte[] metadata) {
            if(!Ready)throw new IOException("Tailscale 节点已离线。");
            // Cap the advertised MSS in SYN/SYN-ACK packets before recomputing checksums.
            ClampMss(packet,length);
            if (!Divert.WinDivertHelperCalcChecksums(packet,(uint)length,metadata,0)) throw new IOException("IPv4 checksum failed.");
            var frame=new byte[length+2];
            frame[0]=(byte)(length>>8);frame[1]=(byte)length;
            Buffer.BlockCopy(packet,0,frame,2,length);
            if (!queue.TryAdd(frame)) throw new IOException("Tailscale 出口正忙。");
        }
        internal static void ClampMss(byte[] packet,int length) {
            int tcp=(packet[0]&15)*4;
            if (packet[9]!=6 || tcp<20 || tcp+20>length || (packet[tcp+13]&2)==0) return;
            int end=tcp+(packet[tcp+12]>>4)*4;
            if (end>length) return;
            for (int i=tcp+20;i<end;) {
                int kind=packet[i];if(kind==0)break;if(kind==1){i++;continue;}
                if(i+1>=end)break;int size=packet[i+1];if(size<2||i+size>end)break;
                if(kind==2 && size==4 && ((packet[i+2]<<8)|packet[i+3])>1240){packet[i+2]=4;packet[i+3]=216;}
                i+=size;
            }
        }
        void WritePackets() {
            try { var stream=child.StandardInput.BaseStream;
                foreach(var frame in queue.GetConsumingEnumerable()){
                    stream.Write(frame,0,frame.Length);
                    if(queue.Count==0)stream.Flush();
                }
            } catch (Exception) { state="error"; }
        }
        void ReadPackets() {
            try { var stream=child.StandardOutput.BaseStream;
                while(Volatile.Read(ref closed)==0){
                    int high=stream.ReadByte(),low=stream.ReadByte();
                    if(high<0 || low<0)break;
                    int length=(high<<8)|low;
                    if(length<20)break;
                    byte[] packet=GatewayDns.Read(stream,length);
                    if(Ready){ClampMss(packet,length);receive(packet);}
                }
            } catch(Exception) { } finally {state="error";}
        }
        public void Dispose() {
            if(Interlocked.Exchange(ref closed,1)!=0)return;
            queue.CompleteAdding();
            try { if(!child.HasExited)child.Kill(); } catch(InvalidOperationException) {}
            try { child.WaitForExit(2000); } finally { child.Dispose(); }
        }
    }
}

