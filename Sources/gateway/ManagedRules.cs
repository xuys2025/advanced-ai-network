using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace AdvancedAINetwork.Gateway {
    public sealed class ManagedRules {
        public const string Url=AiCompatibility.S_4e761e3e983fc0;
        public string[] roots,exact,keywords,processes,ipv4,announced;
        public uint[] asns;
        public string sha256,revision;
        struct Range {internal uint net,mask;}
        Range[] ranges;
        HashSet<string> processSet;
        static uint Number(byte[] x,int i){return ((uint)x[i]<<24)|((uint)x[i+1]<<16)|((uint)x[i+2]<<8)|x[i+3];}
        static Range Network(string s){
            var pair=s.Split('/'); IPAddress ip;int bits;
            if(pair.Length!=2||!IPAddress.TryParse(pair[0],out ip)||ip.AddressFamily!=AddressFamily.InterNetwork||ip.ToString()!=pair[0]||
                !int.TryParse(pair[1],out bits)||bits<8||bits>32)throw new InvalidDataException("Invalid IPv4 network: "+s);
            uint n=Number(ip.GetAddressBytes(),0), mask=uint.MaxValue<<(32-bits);
            uint end=n|~mask;
            if((n&mask)!=n||n<0x01000000||end>=0xe0000000||Overlap(n,end,0x0a000000,0x0affffff)||Overlap(n,end,0x64400000,0x647fffff)||
               Overlap(n,end,0x7f000000,0x7fffffff)||Overlap(n,end,0xa9fe0000,0xa9feffff)||Overlap(n,end,0xac100000,0xac1fffff)||
               Overlap(n,end,0xc0a80000,0xc0a8ffff)||Overlap(n,end,0xc6120000,0xc613ffff))throw new InvalidDataException("Non-public or unaligned network: "+s);
            return new Range{net=n,mask=mask};
        }
        static bool Overlap(uint start,uint end,uint low,uint high){return start<=high && end>=low;}
        static string[] Sorted(IEnumerable<string> xs){return xs.Distinct(StringComparer.Ordinal).OrderBy(x=>x,StringComparer.Ordinal).ToArray();}
        static string Proc(string x){return x.EndsWith(".exe",StringComparison.OrdinalIgnoreCase)?x.Substring(0,x.Length-4):x;}
        public bool MatchesProcess(string name){return name!=null&&processSet.Contains(Proc(name));}
        public bool MatchesIp(byte[] packet,int start){
            uint dest=Number(packet,start);foreach(var r in ranges)if((dest&r.mask)==r.net)return true;return false;
        }
        public static string Digest(string s){using(var hash=SHA256.Create())return BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(s))).Replace("-","").ToLowerInvariant();}
        public void Prepare(){
            ranges=ipv4.Concat(announced).Distinct().Select(Network).ToArray();
            processSet=new HashSet<string>(processes.Select(Proc),StringComparer.OrdinalIgnoreCase);
            revision=Digest(sha256+"\n"+string.Join("\n",announced));
        }
        public static ManagedRules Parse(string input){
            var domain=new List<string>(new[]{"api.ipify.org","icanhazip.com","ifconfig.me","ip.net.coffee"});
            var suffix=new List<string>();var words=new List<string>();var names=new List<string>();var nets=new List<string>();var numbers=new List<uint>();
            bool payload=false;int count=0;
            foreach(string raw in input.TrimStart('\uFEFF').Split('\n')){
                string line=raw.Trim();if(line==""||line.StartsWith("#"))continue;
                if(!payload&&line=="payload:"){payload=true;continue;}
                if(!payload||!line.StartsWith("- ")||++count>2048)throw new InvalidDataException("Unexpected rule syntax");
                var f=line.Substring(2).Trim().Split(',');if(f.Length<2||f.Length>3)throw new InvalidDataException("Invalid rule");
                string type=f[0],v=f[1];bool network=type=="IP-CIDR"||type=="IP-CIDR6"||type=="IP-ASN";
                if(f.Length==3&&(!network||f[2]!="no-resolve"))throw new InvalidDataException("Invalid rule option");
                if(type=="DOMAIN"||type=="DOMAIN-SUFFIX"){
                    v=v.ToLowerInvariant();if(v.Length>253||!Regex.IsMatch(v,@"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\z"))
                        throw new InvalidDataException("Invalid domain");
                    (type=="DOMAIN"?domain:suffix).Add(v);
                }else if(type=="DOMAIN-KEYWORD"){
                    if(!Regex.IsMatch(v,@"\A[a-zA-Z0-9][a-zA-Z0-9.-]{2,62}\z"))throw new InvalidDataException("Invalid keyword");words.Add(v.ToLowerInvariant());
                }else if(type=="PROCESS-NAME"){
                    if(!Regex.IsMatch(v,@"\A[A-Za-z0-9][A-Za-z0-9_. -]{0,79}\z"))throw new InvalidDataException("Invalid program name");
                    if(new[]{"system","svchost","gatewayservice","advancedainetworkguard","verge-mihomo","sing-box"}.Contains(Proc(v),StringComparer.OrdinalIgnoreCase))throw new InvalidDataException("Infrastructure process is not a valid target");
                    names.Add(v);
                }else if(type=="IP-CIDR"){Network(v);nets.Add(v);}
                else if(type=="IP-ASN"){uint n;if(!uint.TryParse(v,NumberStyles.None,CultureInfo.InvariantCulture,out n)||n==0||n==uint.MaxValue)throw new InvalidDataException("Invalid ASN");numbers.Add(n);}
                else if(type=="IP-CIDR6"){var a=v.Split('/');IPAddress ip;int b;if(a.Length!=2||!IPAddress.TryParse(a[0],out ip)||ip.AddressFamily!=AddressFamily.InterNetworkV6||!int.TryParse(a[1],out b)||b<1||b>128)throw new InvalidDataException("Invalid IPv6 rule");}
                else throw new InvalidDataException("Unsupported rule type: "+type);
            }
            if(count<1||names.Count==0||nets.Count==0||numbers.Count==0||!suffix.Contains(AiCompatibility.S_d318762d9a7b1e)||!suffix.Contains(AiCompatibility.S_743e483ae01f1f)||numbers.Distinct().Count()>16)throw new InvalidDataException("Incomplete or unexpected 高级公司 list");
            return new ManagedRules{roots=Sorted(suffix),exact=Sorted(domain),keywords=Sorted(words),processes=Sorted(names),ipv4=Sorted(nets),
                asns=numbers.Distinct().OrderBy(x=>x).ToArray(),announced=new string[0],sha256=Digest(input)};
        }
        public sealed class Ris {public string status;public RisData data;}
        public sealed class RisData {public string resource,query_endtime;public Prefix[] prefixes;}
        public sealed class Prefix {public string prefix;public Period[] timelines;}
        public sealed class Period {public string endtime;}
        public static IEnumerable<string> ActiveV4(uint asn,string json){
            var response=new JavaScriptSerializer().Deserialize<Ris>(json);var d=response.data;
            DateTime end;
            if(response.status!="ok"||d==null||d.resource!=asn.ToString(CultureInfo.InvariantCulture)||d.prefixes==null||
                !DateTime.TryParse(d.query_endtime,CultureInfo.InvariantCulture,DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out end)||
                (DateTime.UtcNow-end).TotalDays>3||end>DateTime.UtcNow.AddHours(1))throw new InvalidDataException("Unusable ASN announcement response");
            foreach(var p in d.prefixes.Where(p=>p.timelines!=null&&p.timelines.Any(t=>t.endtime==d.query_endtime)&&!p.prefix.Contains(":"))){Network(p.prefix);yield return p.prefix;}
        }
        public string DnsSource(){return new JavaScriptSerializer().Serialize(new{version=3,rules=new[]{new{domain=exact,domain_suffix=roots,domain_keyword=keywords}}});}
        public string Provider(bool domainsOnly){
            var lines=roots.Select(x=>"DOMAIN-SUFFIX,"+x).Concat(exact.Select(x=>"DOMAIN,"+x)).Concat(keywords.Select(x=>"DOMAIN-KEYWORD,"+x));
            if(!domainsOnly)lines=lines.Concat(processes.Select(x=>"PROCESS-NAME,"+x)).Concat(ipv4.Concat(announced).Distinct().Select(x=>"IP-CIDR,"+x+",no-resolve")).Concat(asns.Select(x=>"IP-ASN,"+x+",no-resolve"));
            return "payload:\n"+string.Join("\n",lines.Select(x=>"  - "+x))+"\n";
        }
    }
}
