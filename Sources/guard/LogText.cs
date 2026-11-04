using System;
using System.Text.RegularExpressions;

namespace AdvancedAINetwork {
public static class LogText {
    static readonly Regex Osc=new Regex("\u001b\\][^\u0007\u001b]*(?:\u0007|\u001b\\\\)");
    static readonly Regex Csi=new Regex("(?:\u001b\\[|\u009b)[0-?]*[ -/]*[@-~]");
    static readonly Regex Controls=new Regex("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]");
    public static string Clean(string text){if(String.IsNullOrEmpty(text))return "";return Controls.Replace(Csi.Replace(Osc.Replace(text,""),""),"");}
}
public sealed class CoreLogFormatter {
    readonly object sync=new object();bool starting,notified;string deferred;
    static readonly Regex NotReady=new Regex(@"\bERROR\b(?:\s+\[[^\]\r\n]*\])?\s+(?:dns: lookup failed for|router: lookup) api\.ipify\.org: endpoint is not ready yet\s*$",RegexOptions.CultureInvariant);
    public void BeginStartup(){lock(sync){starting=true;notified=false;deferred=null;}}
    public string Format(string raw){string text=LogText.Clean(raw);lock(sync){if(starting&&NotReady.IsMatch(text)){deferred=text;if(notified)return null;notified=true;return "等待隧道就绪…";}return text;}}
    public string Complete(bool success){lock(sync){string result=!success&&deferred!=null?"ERROR 隧道连接失败；最后一条核心提示："+deferred:null;starting=false;notified=false;deferred=null;return result;}}
}
}
