using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace AdvancedAINetwork {
public static class GuardPolicy {
    public const string Version="0.4.1",Prefix="198.19.64.0/18",InterfaceName="AdvancedAINetwork-TUN";
    public const int GatewayPort=17892,VerifiedPort=17893;
    public static string DirectoryPath {get{return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"AdvancedAINetworkGuard");}}
    public static bool Synthetic(string value){IPAddress ip;if(!IPAddress.TryParse(value,out ip)||ip.AddressFamily!=System.Net.Sockets.AddressFamily.InterNetwork)return false;byte[] b=ip.GetAddressBytes();return b[0]==198&&b[1]==19&&b[2]>=64&&b[2]<128;}
    public static string Address(int index){if(index<1||index>8192)throw new Exception("Protected address capacity exceeded.");return "198.19."+(64+index/256)+"."+(index%256);}
    public static object TunConfig(){var config=Data.Obj(
        "log",Data.Obj("level","warn","timestamp",true),
        "dns",Data.Obj("servers",new[]{Data.Obj("type","tcp","tag","guard-dns","server","127.0.0.2","server_port",53),Data.Obj("type","local","tag","adapter-dns","prefer_go",true)},
            "rules",new[]{Data.Obj("inbound",new[]{"policy-dns"},"domain",Data.Exact,"domain_suffix",Data.Roots,"domain_keyword",Data.Keywords,"action","route","server","guard-dns"),
                Data.Obj("inbound",new[]{"policy-dns"},"action","route","server","adapter-dns"),Data.Obj("action","reject","no_drop",true)},"disable_cache",true),
        "inbounds",new[]{Data.Obj("type","tun","tag","protected-tun","interface_name",InterfaceName,"address",new[]{"172.31.254.1/30"},"mtu",1400,"auto_route",true,"route_address",new[]{Prefix},"strict_route",false,"dns_mode","disabled","stack","mixed"),
            Data.Obj("type","direct","tag","policy-dns","listen","127.0.0.3","listen_port",53)},
        "outbounds",new[]{Data.Obj("type","http","tag","guard-mapping","server","127.0.0.2","server_port",GatewayPort,"connect_timeout","3s")},
        "route",Data.Obj("auto_detect_interface",true,"rules",new[]{Data.Obj("inbound",new[]{"policy-dns"},"action","hijack-dns"),Data.Obj("ip_cidr",new[]{Prefix},"network","tcp","port",new[]{80,443},"action","route","outbound","guard-mapping"),Data.Obj("action","reject","no_drop",true)}));
        if(File.Exists(Data.ManagedDomainsPath)){
            var route=(Dictionary<string,object>)config["route"];
            route["rule_set"]=new[]{Data.Obj("tag","live-domains","type","local","format","source","path",Data.ManagedDomainsPath)};
            var dns=(Dictionary<string,object>)config["dns"];
            var rules=(Dictionary<string,object>[])dns["rules"];
            rules[0]=Data.Obj("inbound",new[]{"policy-dns"},"rule_set",new[]{"live-domains"},"action","route","server","guard-dns");
        }
        return config;}
    public static Dictionary<string,object> Status(){
        string path=Path.Combine(DirectoryPath,"guard-status.json");
        using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))using(var reader=new StreamReader(file)){
            var result=Data.Parse(reader.ReadToEnd());DateTime heartbeat;
            if(!DateTime.TryParse(Data.Str(result,"updated_utc"),null,System.Globalization.DateTimeStyles.RoundtripKind,out heartbeat)||(DateTime.UtcNow-heartbeat.ToUniversalTime()).TotalSeconds>15)throw new Exception("保护服务状态已过期，限制保留。");
            return result;
        }
    }
}
}
