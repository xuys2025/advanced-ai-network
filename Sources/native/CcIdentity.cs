using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace AdvancedAINetwork {
public static class CcIdentity {
    public static string Kind(string kind){if(kind!="code"&&kind!="desktop")throw new Exception("不支持的 高级 AI 程序类型。");return kind;}
    public static string Normalize(string path){
        if(String.IsNullOrWhiteSpace(path)||path.Length>1000||!Path.IsPathRooted(path)||path.StartsWith("\\\\")||path.StartsWith("\\?" )||path.IndexOfAny(new[]{'"','\r','\n','*','?'})>=0)throw new Exception("请选择本机官方 高级 AI Code 原生程序。");
        path=Path.GetFullPath(path);if(path.Length<3||path[1]!=':'||!File.Exists(path))throw new Exception("CC 主程序不存在。");return path;
    }
    public static string DefaultPath(){string path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),".local","bin",AiCompatibility.S_11b496da7187c8);return File.Exists(path)?path:"";}
    public static string DesktopPackagePath(){
        string script=AiCompatibility.S_31d0e2b9be741b;
        var start=new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"WindowsPowerShell","v1.0","powershell.exe"),"-NoProfile -NonInteractive -EncodedCommand "+Convert.ToBase64String(Encoding.Unicode.GetBytes(script))){UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,StandardOutputEncoding=Encoding.UTF8};
        using(var p=Process.Start(start)){var output=p.StandardOutput.ReadToEndAsync();var error=p.StandardError.ReadToEndAsync();if(!p.WaitForExit(15000)){try{p.Kill();}catch{}throw new Exception("读取 Desktop 安装信息超时，请重试或选择程序文件。");}string path=output.GetAwaiter().GetResult().Trim();if(p.ExitCode==0&&File.Exists(path))return path;}
        return "";
    }
    public static string DesktopPath(){
        string packaged=DesktopPackagePath();if(packaged.Length>0)return packaged;
        string root=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),AiCompatibility.S_5220fe254e6170);
        if(Directory.Exists(root)){var directories=Directory.GetDirectories(root,"app-*");Array.Sort(directories,(a,b)=>{Version av,bv;Version.TryParse(Path.GetFileName(a).Substring(4),out av);Version.TryParse(Path.GetFileName(b).Substring(4),out bv);return Comparer<Version>.Default.Compare(bv,av);});foreach(string directory in directories){string path=Path.Combine(directory,AiCompatibility.S_11b496da7187c8);if(File.Exists(path))return path;}}
        string fallback=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Programs",AiCompatibility.S_0615570f9ea136,AiCompatibility.S_14cdc2a91401b7);return File.Exists(fallback)?fallback:"";
    }
    public static string Hash(Stream stream){stream.Position=0;using(var sha=SHA256.Create()){string value=BitConverter.ToString(sha.ComputeHash(stream)).Replace("-","").ToLowerInvariant();stream.Position=0;return value;}}
    public static string FinalPath(FileStream file){var value=new StringBuilder(2048);uint count=GetFinalPathNameByHandle(file.SafeFileHandle,value,value.Capacity,0);if(count==0||count>=value.Capacity)throw new Exception("无法确认 CC 实际程序路径。");string path=value.ToString();if(path.StartsWith("\\\\?\\UNC\\",StringComparison.OrdinalIgnoreCase))throw new Exception("不支持网络共享程序。");if(path.StartsWith("\\\\?\\"))path=path.Substring(4);return path;}
    public static Dictionary<string,object> Verify(string file,string kind="code"){
        Kind(kind);
        var info=new WinTrustFile(file);var data=new WinTrustData();IntPtr pointer=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WinTrustFile)));uint result;
        try{Marshal.StructureToPtr(info,pointer,false);data.File=pointer;Guid action=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");try{result=WinVerifyTrust(new IntPtr(-1),ref action,data);}finally{data.StateAction=2;WinVerifyTrust(new IntPtr(-1),ref action,data);}}
        finally{Marshal.DestroyStructure(pointer,typeof(WinTrustFile));Marshal.FreeHGlobal(pointer);}
        if(result!=0)throw new Exception("CC 数字签名未通过 Windows 验证（0x"+result.ToString("X8")+"），未启动程序。");
        using(var certificate=new X509Certificate2(X509Certificate.CreateFromSignedFile(file))){string publisher=certificate.GetNameInfo(X509NameType.SimpleName,false);var version=FileVersionInfo.GetVersionInfo(file);
            if(publisher!=AiCompatibility.S_9e679834778a71||version.ProductName!=(kind=="code"?AiCompatibility.S_246ef8c1130d56:AiCompatibility.S_0615570f9ea136)||(kind=="desktop"&&!String.Equals(version.OriginalFilename,AiCompatibility.S_11b496da7187c8,StringComparison.OrdinalIgnoreCase)))throw new Exception("签名或产品标识不是所选的官方 高级 AI 程序，未扩大到其他软件。");
            return new Dictionary<string,object>{{"kind",kind},{"publisher",publisher},{"product",version.ProductName},{"version",version.ProductVersion??""},{"signature_valid",true}};
        }
    }
    public static object Inspect(string path,string kind="code"){path=Normalize(path);using(var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){string canonical=FinalPath(file);var result=Verify(canonical,kind);result["path"]=path;result["canonical_path"]=canonical;return result;}}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]class WinTrustFile {public uint Size=(uint)Marshal.SizeOf(typeof(WinTrustFile));[MarshalAs(UnmanagedType.LPWStr)]public string Path;public IntPtr Handle=IntPtr.Zero,KnownSubject=IntPtr.Zero;public WinTrustFile(string path){Path=path;}}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]class WinTrustData {public uint Size=(uint)Marshal.SizeOf(typeof(WinTrustData));public IntPtr PolicyCallback=IntPtr.Zero,SipData=IntPtr.Zero;public uint UiChoice=2,RevocationChecks=0,UnionChoice=1;public IntPtr File=IntPtr.Zero;public uint StateAction=1;public IntPtr State=IntPtr.Zero;[MarshalAs(UnmanagedType.LPWStr)]public string Url=null;public uint ProviderFlags=0x1000,UiContext=0;public IntPtr SignatureSettings=IntPtr.Zero;}
    [DllImport("wintrust.dll",ExactSpelling=true,CharSet=CharSet.Unicode)]static extern uint WinVerifyTrust(IntPtr window,ref Guid action,[In,Out]WinTrustData data);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]static extern uint GetFinalPathNameByHandle(SafeFileHandle file,StringBuilder path,int capacity,uint flags);
}
}
