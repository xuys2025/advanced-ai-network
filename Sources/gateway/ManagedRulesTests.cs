using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;
public class ManagedRulesTests {
    static void Check(bool ok,string detail){if(!ok)throw new Exception(detail);}
    static bool Match(ManagedRules p,string ip){return p.MatchesIp(IPAddress.Parse(ip).GetAddressBytes(),0);}
    public static int Main(string[] args){
        var raw=File.ReadAllText(args[0]);var p=ManagedRules.Parse(raw);
        p.announced=ManagedRules.ActiveV4(399358,File.ReadAllText(args[1])).OrderBy(x=>x,StringComparer.Ordinal).ToArray();p.Prepare();
        Check(Match(p,"160.79.104.0")&&Match(p,"160.79.111.255")&&!Match(p,"160.79.103.255")&&!Match(p,"160.79.112.0"),"CIDR edges");
        Check(p.MatchesProcess(AiCompatibility.S_25d2fedb323143)&&p.MatchesProcess(AiCompatibility.S_0615570f9ea136)&&p.MatchesProcess("CoWoRk-SvC.ExE")&&!p.MatchesProcess(AiCompatibility.S_0e36ada40747b4),"program OR");
        var copy=ManagedRules.Parse(raw);copy.announced=new[]{"198.51.100.0/24"};copy.Prepare();
        Check(Match(copy,"198.51.100.17")&&!Match(copy,"198.51.101.17"),"ASN-only match");
        foreach(var bad in new[]{"MATCH,other","IP-CIDR,0.0.0.0/0","IP-CIDR,192.168.10.0/24","PROCESS-NAME,*","DOMAIN-SUFFIX,com","IP-ASN,nope","DOMAIN-KEYWORD,."}){
            bool rejected=false;try{ManagedRules.Parse(raw+"\n  - "+bad);}catch(InvalidDataException){rejected=true;}Check(rejected,"accepted unsafe rule "+bad);
        }
        var serial=new JavaScriptSerializer();
        File.WriteAllText(Path.Combine(args[2],"managed-rules.json"),serial.Serialize(p));
        File.WriteAllText(Path.Combine(args[2],"managed-domains.json"),p.DnsSource());
        Console.WriteLine("PASS: IPv4 boundaries, ASN-only match, process names, unrelated traffic and rejection of invalid input. "+p.revision);
        return 0;
    }
}
