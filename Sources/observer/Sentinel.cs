using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

internal static class Sentinel {
    const string Title="高级 AI 联网保护";
    internal sealed class Alerts {
        internal string State {get;private set;}
        int pid;
        long firstUncertain=-1;
        int uncertainPid;
        internal Alerts(){State="";}
        internal bool Transition(string state,int currentPid,long elapsedMs){
            if(state=="unknown" && State!="unknown"){
                if(firstUncertain<0||uncertainPid!=currentPid){firstUncertain=elapsedMs;uncertainPid=currentPid;}
                if(elapsedMs-firstUncertain<5000)return false;
            }else firstUncertain=-1;
            if(state==State && pid==currentPid)return false;
            State=state;pid=currentPid;return true;
        }
    }
    internal static string ChangedIp(string oldIp,string newIp){
        return !string.IsNullOrEmpty(oldIp)&&oldIp!=newIp?"公网 IP 从 "+oldIp+" 变为 "+newIp+"。专用网关已连通。":null;
    }
    static void WriteReport(string path,object value){Protection.Save(Path.GetFullPath(path),value);}
    [STAThread] static int Main(string[] args){
        Application.EnableVisualStyles();
        if(args.Length==2 && args[0]=="--check-report"){
            try{WriteReport(args[1],new{pass=true,egress=Protection.Check(),backend=Protection.Inspect()});return 0;}
            catch(Exception ex){WriteReport(args[1],new{pass=false,error=ex.Message});return 1;}
        }
        if(args.Length==1 && args[0]=="--check"){
            try{var exit=Protection.Check();MessageBox.Show("已通过 "+exit.gateway+" 完成 HTTPS 检查。\n公网 IP："+exit.ip+"  "+exit.country+"\n检查时间："+exit.measuredUtc.ToLocalTime().ToString("HH:mm:ss"),Title,MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;}
            catch(Exception ex){MessageBox.Show(ex.Message+"\n请先暂停发送，待出口检查通过再继续。",Title,MessageBoxButtons.OK,MessageBoxIcon.Warning);return 1;}
        }
        if(args.Length==1 && args[0]=="--pause"){
            try{Protection.Pause();MessageBox.Show("暂停设置已保存，Windows 已拒绝测试程序连接本机代理。\n需要恢复时，打开「高级 AI 专用网络」并选择「恢复连接」。",Title,MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;}
            catch(Exception ex){MessageBox.Show("无法确认紧急暂停。请先退出桌面端和 CLI。\n"+ex.Message,Title,MessageBoxButtons.OK,MessageBoxIcon.Error);return 1;}
        }
        if(args.Length==1 && args[0]=="--test"){
            return ChangedIp("203.0.113.5","203.0.113.6")!=null && ChangedIp("203.0.113.5","203.0.113.5")==null && ChangedIp(null,"203.0.113.6")==null ? 0 : 1;
        }
        if(args.Length!=0 && !(args.Length==1&&args[0]=="--watch"))return 2;
        bool first;
        using(var mutex=new Mutex(true,@"Local\AdvancedAINetworkProtectionObserver-v1",out first)){
            if(!first)return 0;
            using(var watch=new Watch()){Application.Run(watch);}
        }return 0;
    }
    sealed class Watch : ApplicationContext {
        readonly NotifyIcon tray=new NotifyIcon();
        readonly System.Windows.Forms.Timer timer=new System.Windows.Forms.Timer();
        readonly string latest=Path.Combine(Protection.Data,"last-egress.json");
        readonly string journal=Path.Combine(Protection.Data,"events.jsonl");
        readonly string status=Path.Combine(Protection.Data,"observer.json");
        readonly ToolStripMenuItem summary=new ToolStripMenuItem("正在读取网关状态");
        readonly Alerts alerts=new Alerts();
        readonly Stopwatch clock=Stopwatch.StartNew();
        string previousIp="",probeIssue="",lastNotice="",lastRaw="";
        int pendingPid,unconfirmedChecks;
        readonly int observerPid, sessionId;
        DateTime nextProbe=DateTime.MinValue,nextHeartbeat=DateTime.MinValue,lastProbe=DateTime.MinValue;
        Task<Protection.Egress> pending;
        public Watch(){
            using(var me=Process.GetCurrentProcess()){observerPid=me.Id;sessionId=me.SessionId;}
            Directory.CreateDirectory(Protection.Data);
            try{previousIp=Protection.Str(Protection.Read(latest),"ip");}catch(IOException){}catch(ArgumentException){}catch(InvalidOperationException){}
            summary.Enabled=false;var menu=new ContextMenuStrip();menu.Items.Add(summary);menu.Items.Add(new ToolStripSeparator());
            menu.Items.Add("立即检查专用出口",null,(s,e)=>Launch("--check"));
            menu.Items.Add("紧急暂停高级 AI 联网",null,(s,e)=>Launch("--pause"));
            menu.Items.Add("打开提醒记录",null,(s,e)=>{if(File.Exists(journal))Process.Start(new ProcessStartInfo(Path.Combine(Environment.SystemDirectory,"notepad.exe"),"\""+journal+"\""){UseShellExecute=false});});
            tray.ContextMenuStrip=menu;tray.Icon=SystemIcons.Information;tray.Text=Title;tray.Visible=true;tray.DoubleClick+=(s,e)=>Launch("--check");
            timer.Interval=2000;timer.Tick+=(s,e)=>Poll();timer.Start();Poll();
        }
        static void Launch(string arg){Process.Start(new ProcessStartInfo(Application.ExecutablePath,arg){UseShellExecute=false});}
        void Record(string kind,string text){
            try{
                if(File.Exists(journal)&&new FileInfo(journal).Length>512*1024){string old=journal+".previous";if(File.Exists(old))File.Delete(old);File.Move(journal,old);}
                string line=new JavaScriptSerializer().Serialize(new{time=DateTimeOffset.Now.ToString("o"),kind=kind,message=text});
                File.AppendAllText(journal,line+Environment.NewLine,Protection.Utf8);
            }catch(IOException){}catch(UnauthorizedAccessException){}
        }
        void Notice(string kind,string text,ToolTipIcon icon){
            lastNotice=text;Record(kind,text);tray.ShowBalloonTip(10000,Title,text,icon);
        }
        void Poll(){
            var v=Protection.Inspect();DateTime now=DateTime.UtcNow;
            string previousState=alerts.State;
            bool changed=alerts.Transition(v.state,v.pid,clock.ElapsedMilliseconds);
            string raw=v.state+"/"+v.detail;
            if(v.state=="unknown" && raw!=lastRaw)Record("sample-recheck",v.message+" "+v.detail);
            lastRaw=raw;
            if(changed){
                if(!v.Ready){Notice(v.state,v.message+" "+v.detail,v.state=="paused"?ToolTipIcon.Info:ToolTipIcon.Warning);probeIssue="";lastProbe=DateTime.MinValue;unconfirmedChecks=0;}
                else{
                    if(previousState!="")Notice("backend-restored","网关后台已就绪，正在核对实际出口。",ToolTipIcon.Info);
                    else Record("observer-started","开始监测网关与保护状态。");
                    nextProbe=DateTime.MinValue;lastProbe=DateTime.MinValue;
                }
            }
            if(pending!=null && pending.IsCompleted){
                try{
                    var sample=pending.GetAwaiter().GetResult();
                    if(v.Ready && sample.servicePid==v.pid && sample.gateway==v.gateway){
                        var change=ChangedIp(previousIp,sample.ip);
                        if(change!=null)Notice("public-ip-changed",DateTime.Now.ToString("HH:mm:ss")+" "+change,ToolTipIcon.Info);
                        else if(probeIssue!="")Notice("egress-restored","专用出口检查恢复，公网 IP 为 "+sample.ip+"。",ToolTipIcon.Info);
                        if(previousIp=="" || change!=null)Protection.Save(latest,new{ip=sample.ip,country=sample.country,observed_utc=sample.measuredUtc.ToString("o")});
                        previousIp=sample.ip;lastProbe=sample.measuredUtc;probeIssue="";unconfirmedChecks=0;
                    }
                }catch(Protection.StatusUnconfirmed ex){
                    if(v.Ready && pendingPid==v.pid){
                        if(++unconfirmedChecks<=2){Record("check-retry",ex.Message);nextProbe=now.AddSeconds(2);}
                        else{if(probeIssue=="")Notice("check-status-unconfirmed","状态多次无法核实，出口检查尚未完成。",ToolTipIcon.Warning);probeIssue=ex.Message;}
                    }
                }catch(Exception ex){
                    if(v.Ready && pendingPid==v.pid){if(probeIssue=="")Notice("egress-unverified","专用出口检查失败。请先检查出口再发送。",ToolTipIcon.Warning);probeIssue=ex.Message;Record("check-error",ex.Message);}
                }
                pending=null;
            }
            if(v.Ready&&pending==null&&now>=nextProbe){
                nextProbe=now.AddSeconds(60);pendingPid=v.pid;pending=Task.Run((Func<Protection.Egress>)Protection.Check);
            }
            string visible=!v.Ready?v.message:probeIssue!=""?"专用出口检查失败":lastProbe==DateTime.MinValue?"正在核对专用出口":"专用出口正常 · "+previousIp;
            summary.Text=visible;string tip=Title+" · "+visible;tray.Text=tip.Substring(0,Math.Min(63,tip.Length));
            tray.Icon=!v.Ready||probeIssue!=""?SystemIcons.Warning:SystemIcons.Information;
            if(changed||now>=nextHeartbeat){
                try{Protection.Save(status,new{pid=observerPid,session=sessionId,state=v.state,service_pid=v.pid,gateway=v.gateway,ip=previousIp,last_check_utc=lastProbe==DateTime.MinValue?"":lastProbe.ToString("o"),probe_error=probeIssue,last_notice=lastNotice,updated_utc=now.ToString("o")});}
                catch(IOException){}catch(UnauthorizedAccessException){}
                nextHeartbeat=now.AddSeconds(5);
            }
        }
        protected override void Dispose(bool disposing){
            if(disposing){timer.Stop();timer.Dispose();tray.Visible=false;tray.ContextMenuStrip.Dispose();tray.Dispose();}
            base.Dispose(disposing);
        }
    }
}
