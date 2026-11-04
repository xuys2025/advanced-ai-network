using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Principal;
using System.Text;
using System.Threading;
namespace AdvancedAINetwork {
public static class Lifecycle {
    public const string Version="0.6.4";
    public static string InstanceName {get{return "Local\\AdvancedAIPrivateNetwork-"+WindowsIdentity.GetCurrent().User.Value;}}
    public static void Log(string message){try{string path=Path.Combine(Data.State,"runtime.log");if(File.Exists(path)&&new FileInfo(path).Length>512*1024){File.Copy(path,path+".previous",true);File.WriteAllText(path,"");}File.AppendAllText(path,DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss")+"  "+LogText.Clean(message)+Environment.NewLine,new UTF8Encoding(false));}catch{}}
}
public static class ExitIntent {
    public static string Marker(string token){Guid parsed;if(!Guid.TryParseExact(token,"N",out parsed))throw new ArgumentException("Invalid launch token.");return Path.Combine(Data.State,"exit-intent-"+parsed.ToString("N")+".json");}
    public static bool Consume(string token){string marker=Marker(token);if(!File.Exists(marker))return false;File.Delete(marker);return true;}
}
public static class DesktopLauncher {
    [STAThread] public static int Main(string[] args){bool created;using(var mutex=new Mutex(true,Lifecycle.InstanceName+"-Launcher",out created)){
        if(!created){Process.Start(new ProcessStartInfo(Path.Combine(Data.Home,"AdvancedAINetwork.exe")){UseShellExecute=false});return 0;}
        int delay=5;bool tested=false;while(true){try{string launchArgs=args.Contains("--startup")?"--startup":"--managed";if(!tested&&args.Length==2&&args[0]=="--self-test"){if(args[1].Contains("\""))return 1;launchArgs="--self-test \""+args[1]+"\"";tested=true;}string token=Guid.NewGuid().ToString("N");launchArgs+=" --launch-token "+token;var start=new ProcessStartInfo(Path.Combine(Data.Home,"AdvancedAINetwork.exe"),launchArgs){UseShellExecute=false,WorkingDirectory=Data.Home};int code;DateTime began=DateTime.UtcNow;using(var child=Process.Start(start)){Lifecycle.Log("启动器已拉起 Electron，进程 "+child.Id+"。");child.WaitForExit();code=child.ExitCode;}bool requested=ExitIntent.Consume(token);Lifecycle.Log("Electron 已退出，退出码="+code+"，明确退出="+requested+"。");if(requested)return 0;Lifecycle.Log("Electron 未经明确退出而结束，"+delay+" 秒后恢复；域名保护保留。");Thread.Sleep(delay*1000);delay=(DateTime.UtcNow-began).TotalMinutes>=2?5:Math.Min(60,delay*2);}catch(Exception ex){Lifecycle.Log("启动器等待恢复："+ex.Message);Thread.Sleep(delay*1000);delay=Math.Min(60,delay*2);}}
    }}
}
}
