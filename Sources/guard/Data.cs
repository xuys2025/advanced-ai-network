using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace AdvancedAINetwork {
public static class Data {
    public const string Group="Advanced-AI-Network", Front="Advanced-AI-Front", Local="Advanced-AI-Network-Local";
    public const int ProxyPort=17891;
    static readonly string[] BuiltInRoots={AiCompatibility.S_d318762d9a7b1e,AiCompatibility.S_c55d5f6562819e,"antspace.dev","clau.de",AiCompatibility.S_743e483ae01f1f,AiCompatibility.S_3c3a75765581d1,AiCompatibility.S_ba35b59b5869e8,AiCompatibility.S_b55da41d0fb07a,AiCompatibility.S_c3b2d321f93f6b,AiCompatibility.S_cceb19833d60dc,AiCompatibility.S_9bf2a517ed3cdf,AiCompatibility.S_4d8d78a2b2b457,AiCompatibility.S_a1101ea07e3e93,AiCompatibility.S_62e4eb09895085,"modelcontextprotocol.com","modelcontextprotocol.io","modelcontextprotocol.net","modelcontextprotocol.org","ant.dev",AiCompatibility.S_e8d2487918725c,AiCompatibility.S_377781691d8cda,AiCompatibility.S_ea80aaae921557,AiCompatibility.S_2d7a1683632e95,"intercom.io","intercomcdn.com","interface.feedback","lcicat.org","lcicollections.org","mcpservertest.online","muthos.com","sentry.io","sillylittleguy.org","statsigapi.net"};
    static readonly string[] BuiltInExact={"api.ipify.org","icanhazip.com","ifconfig.me","ip.net.coffee",AiCompatibility.S_783a5375a32dd3,AiCompatibility.S_7361a0b35b1d80,AiCompatibility.S_1e461caa6d3581,"browser-intake-us5-datadoghq.com","cdn.growthbook.io","cdn.usefathom.com",AiCompatibility.S_10aec8d3389d2c,"storage.googleapis.com"};
    static readonly string[] BuiltInKeywords={"datadog","sentry","sift"};
    public static readonly string[] Namespaces=BuiltInRoots.SelectMany(x=>new[]{x,"."+x}).Concat(BuiltInExact).ToArray();
    public static readonly string ManagedDomainsPath=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkLanGateway","managed-domains.json");
    sealed class DomainSet {public string[] domain,domain_suffix,domain_keyword;}
    sealed class DomainFile {public DomainSet[] rules;}
    static DomainSet live=new DomainSet{domain=BuiltInExact,domain_suffix=BuiltInRoots,domain_keyword=BuiltInKeywords};
    static readonly object domainLock=new object();static long reloadAfter;static DateTime stamp;
    static DomainSet Domains(){
        long now=DateTime.UtcNow.Ticks;
        if(now<Interlocked.Read(ref reloadAfter))return Volatile.Read(ref live);
        lock(domainLock){
            if(now<reloadAfter)return live;
            Interlocked.Exchange(ref reloadAfter,now+TimeSpan.TicksPerSecond);
            var info=new FileInfo(ManagedDomainsPath);
            if(info.Exists&&info.LastWriteTimeUtc!=stamp){
                using(var file=new FileStream(info.FullName,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
                using(var reader=new StreamReader(file)){
                    var parsed=new JavaScriptSerializer().Deserialize<DomainFile>(reader.ReadToEnd()).rules.Single();
                    if(parsed.domain==null||parsed.domain_suffix==null||parsed.domain_keyword==null)throw new InvalidDataException("Incomplete domain manifest");
                    Volatile.Write(ref live,parsed);stamp=info.LastWriteTimeUtc;
                }
            }
            return live;
        }
    }
    public static string[] Roots {get{return Domains().domain_suffix;}}
    public static string[] Exact {get{return Domains().domain;}}
    public static string[] Keywords {get{return Domains().domain_keyword;}}
    public static string PolicyHash {get{using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(Encoding.ASCII.GetBytes(String.Join("\n",Roots.Concat(Exact).Concat(Keywords.Select(x=>"keyword:"+x)).OrderBy(x=>x,StringComparer.Ordinal))))).Replace("-","").ToLowerInvariant();}}
    public static bool Target(string name) { name=name.TrimEnd('.').ToLowerInvariant();return Exact.Contains(name)||Roots.Any(x=>name==x||name.EndsWith("."+x,StringComparison.Ordinal))||Keywords.Any(name.Contains); }
    public static Dictionary<string,object> Obj(params object[] pairs) { var d=new Dictionary<string,object>();for(int i=0;i<pairs.Length;i+=2)d[(string)pairs[i]]=pairs[i+1];return d; }
    public static string Json(object value) { return new JavaScriptSerializer{MaxJsonLength=1024*1024}.Serialize(value); }
    public static Dictionary<string,object> Parse(string value) { return new JavaScriptSerializer{MaxJsonLength=1024*1024}.Deserialize<Dictionary<string,object>>(value); }
    public static string Str(Dictionary<string,object> d,string key,string fallback="") { object v;return d.TryGetValue(key,out v)&&v!=null?Convert.ToString(v):fallback; }
    public static Dictionary<string,object> Map(Dictionary<string,object> d,string key) { object v;return d.TryGetValue(key,out v)?v as Dictionary<string,object>:null; }
    public static IEnumerable<object> Arr(Dictionary<string,object> d,string key) { object v;return d.TryGetValue(key,out v)&&v is IEnumerable ? ((IEnumerable)v).Cast<object>():Enumerable.Empty<object>(); }
    public static string Home {get{return Path.GetDirectoryName(typeof(Data).Assembly.Location);}}
    public static string State {get { string p=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"AdvancedAIPrivateNetwork"); Directory.CreateDirectory(p);return p; }}
    public static void PrivateDirectory(string path) {
        Directory.CreateDirectory(path);var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);
        foreach(var sid in new[]{WindowsIdentity.GetCurrent().User,new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null),new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null)})
            acl.AddAccessRule(new FileSystemAccessRule(sid,FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(acl);
    }
    public static string Hash(string path) {using(var file=File.OpenRead(path))using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(file)).Replace("-","").ToLowerInvariant();}
    public static string PowerShell(string path,string action) {
        return PowerShell(path,action,15000,CancellationToken.None);
    }
    public static string PowerShell(string path,string action,int timeoutMs,CancellationToken token) {
        token.ThrowIfCancellationRequested();
        string shell=Path.Combine(Environment.SystemDirectory,@"WindowsPowerShell\v1.0\powershell.exe");
        var start=new ProcessStartInfo(shell,"-NoProfile -NonInteractive -ExecutionPolicy Bypass -File \""+path+"\" -Action "+action){
            UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,
            StandardOutputEncoding=Encoding.UTF8,StandardErrorEncoding=Encoding.UTF8};
        using(var process=Process.Start(start)){
            var output=process.StandardOutput.ReadToEndAsync();var error=process.StandardError.ReadToEndAsync();
            var time=Stopwatch.StartNew();
            while(!process.WaitForExit(100)){
                if(!token.IsCancellationRequested && time.ElapsedMilliseconds<timeoutMs)continue;
                try{process.Kill();}catch(InvalidOperationException){}
                if(!process.WaitForExit(3000))throw new IOException("维护子进程未按时退出。");
                token.ThrowIfCancellationRequested();
                string stage="启动脚本";
                if(error.Wait(1000))foreach(string line in error.Result.Split('\n'))
                    if(line.StartsWith("guard-stage "))stage=line.Trim().Substring(12);
                throw new TimeoutException(action+" 超时："+stage+"，耗时 "+time.ElapsedMilliseconds+" ms");
            }
            if(!Task.WaitAll(new Task[]{output,error},2000))throw new IOException("系统状态输出超时。");
            if(process.ExitCode!=0)throw new IOException(error.Result.Length>0?error.Result:"系统操作未完成。");
            return output.Result;
        }
    }
}
}
