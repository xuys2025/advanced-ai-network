using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Web.Script.Serialization;
public static class ProtectionAudit {
    static int U16(byte[] b,int p){if(p+2>b.Length)throw new IOException("Short DNS response");return b[p]*256+b[p+1];}
    static byte[] Read(Stream s,int count){var b=new byte[count];for(int p=0;p<count;){int n=s.Read(b,p,count-p);if(n==0)throw new EndOfStreamException();p+=n;}return b;}
    static byte[] Query(string name,int type){var q=new List<byte>{0xca,0x4a,1,0,0,1,0,0,0,0,0,0};foreach(string label in name.Split('.')){q.Add((byte)label.Length);q.AddRange(Encoding.ASCII.GetBytes(label));}q.AddRange(new byte[]{0,0,(byte)type,0,1});return q.ToArray();}
    static bool Check(string name,int type,bool tcp){
        byte[] q=Query(name,type),a;
        if(tcp){using(var c=new TcpClient()){var task=c.ConnectAsync("127.0.0.2",53);if(!task.Wait(2000))throw new IOException("TCP DNS timeout");task.GetAwaiter().GetResult();c.ReceiveTimeout=c.SendTimeout=2000;var s=c.GetStream();s.WriteByte((byte)(q.Length>>8));s.WriteByte((byte)q.Length);s.Write(q,0,q.Length);a=Read(s,U16(Read(s,2),0));}}
        else{using(var c=new UdpClient()){c.Client.ReceiveTimeout=2000;c.Connect("127.0.0.2",53);c.Send(q,q.Length);IPEndPoint peer=null;a=c.Receive(ref peer);}}
        if(a.Length<q.Length||a[0]!=q[0]||a[1]!=q[1]||(a[2]&128)==0||(a[3]&15)!=0||U16(a,4)!=1)throw new IOException("Invalid DNS reply");
        for(int i=12;i<q.Length;i++)if(a[i]!=q[i])throw new IOException("DNS question mismatch");
        if(type!=1)return U16(a,6)==0&&U16(a,8)==0&&U16(a,10)==0;
        int p=q.Length;if(U16(a,6)!=1)return false;
        if((a[p]&192)==192)p+=2;else{while(a[p]!=0){p+=a[p]+1;if(p>=a.Length)throw new IOException("Malformed DNS name");}p++;}
        if(U16(a,p)!=1||U16(a,p+2)!=1||U16(a,p+8)!=4||p+14>a.Length)return false;
        return a[p+10]==198&&a[p+11]==19&&a[p+12]>=64&&a[p+12]<128;
    }
    public static int Main(string[] args){var rows=new List<object>();bool success=true;foreach(string name in new[]{AiCompatibility.S_d318762d9a7b1e,AiCompatibility.S_c55d5f6562819e,"antspace.dev","clau.de",AiCompatibility.S_743e483ae01f1f,AiCompatibility.S_3c3a75765581d1,AiCompatibility.S_ba35b59b5869e8,AiCompatibility.S_b55da41d0fb07a,AiCompatibility.S_c3b2d321f93f6b,AiCompatibility.S_cceb19833d60dc,AiCompatibility.S_9bf2a517ed3cdf,AiCompatibility.S_4d8d78a2b2b457,AiCompatibility.S_a1101ea07e3e93,AiCompatibility.S_62e4eb09895085,"modelcontextprotocol.com","modelcontextprotocol.io","modelcontextprotocol.net","modelcontextprotocol.org","ant.dev",AiCompatibility.S_e8d2487918725c,AiCompatibility.S_377781691d8cda,AiCompatibility.S_ea80aaae921557,AiCompatibility.S_2d7a1683632e95,"intercom.io","intercomcdn.com","interface.feedback","lcicat.org","lcicollections.org","mcpservertest.online","muthos.com","sentry.io","sillylittleguy.org","statsigapi.net","api.ipify.org","icanhazip.com","ifconfig.me","ip.net.coffee",AiCompatibility.S_783a5375a32dd3,AiCompatibility.S_7361a0b35b1d80,AiCompatibility.S_1e461caa6d3581,"browser-intake-us5-datadoghq.com","cdn.growthbook.io","cdn.usefathom.com",AiCompatibility.S_10aec8d3389d2c,"storage.googleapis.com",AiCompatibility.S_0e4a7f621b2756,AiCompatibility.S_1d09f1b58dcbb8})foreach(int type in new[]{1,28,64,65})foreach(bool tcp in new[]{false,true}){bool ok=false;string error="";try{ok=Check(name,type,tcp);}catch(Exception e){error=e.GetBaseException().Message;}success&=ok;rows.Add(new{domain=name,type=type,transport=tcp?"tcp":"udp",passed=ok,error=error});}File.WriteAllText(args[0],new JavaScriptSerializer().Serialize(new{success=success,read_only=true,checked_utc=DateTime.UtcNow.ToString("o"),checks=rows}),new UTF8Encoding(false));Console.WriteLine("DNS protection: "+rows.Count+" checks, success="+success);return success?0:1;}
}
