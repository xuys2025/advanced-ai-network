using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using AdvancedAINetwork;
using Microsoft.Win32;

namespace AdvancedAINetwork.Gateway {
    // Scope is the configured owner's two official Desktop cache locations.
    // Matching a path only nominates it for signature verification.
    internal sealed class EmbeddedCodePaths {
        readonly string[] roots;
        static readonly Regex Version = new Regex(@"\A[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\z", RegexOptions.CultureInvariant);
        static readonly Regex Build = new Regex(@"\A[0-9a-fA-F]{8,64}\z", RegexOptions.CultureInvariant);
        public EmbeddedCodePaths(string profile) {
            profile = Path.GetFullPath(profile).TrimEnd('\\');
            roots = new[] { Path.Combine(profile,AiCompatibility.S_7d73e0dc71b1e3) + "\\", Path.Combine(profile,AiCompatibility.S_ae909a2e1324a3) + "\\" };
        }
        public string Relative(string path) {
            if (string.IsNullOrEmpty(path) || path.Length < 3 || path.IndexOf('/') >= 0 || path.IndexOf(':',2) >= 0) return null;
            foreach (string root in roots) if (path.StartsWith(root,StringComparison.OrdinalIgnoreCase)) {
                string relative = path.Substring(root.Length); string[] parts = relative.Split('\\');
                if (parts.Length == 3 && Version.IsMatch(parts[0]) && Build.IsMatch(parts[1]) && parts[2].Equals(AiCompatibility.S_11b496da7187c8,StringComparison.OrdinalIgnoreCase)) return relative;
            }
            return null;
        }
        public bool Matches(string path) { return Relative(path) != null; }
        public bool SameFileLocation(string logical,string physical) { string a=Relative(logical),b=Relative(physical);return a!=null&&b!=null&&a.Equals(b,StringComparison.OrdinalIgnoreCase); }
        public string[] Aliases(string path) { string relative=Relative(path);return relative==null?new[]{path}:roots.Select(root=>root+relative).ToArray(); }
        public string[] Installed() {
            var result=new List<string>();
            foreach(string root in roots) {
                try {
                    if(!Directory.Exists(root))continue;
                    foreach(string version in Directory.GetDirectories(root)) {
                        if(!Version.IsMatch(Path.GetFileName(version)))continue;
                        foreach(string build in Directory.GetDirectories(version)) {
                            string path=Path.Combine(build,AiCompatibility.S_11b496da7187c8);
                            if(Matches(path)&&File.Exists(path))result.Add(path);
                        }
                    }
                } catch(IOException) {} catch(UnauthorizedAccessException) {}
            }
            return result.ToArray();
        }
        internal static string FromNative(string native,IDictionary<string,string> drives) {
            if(string.IsNullOrEmpty(native))return null;
            foreach(var drive in drives)if(native.StartsWith(drive.Value+"\\",StringComparison.OrdinalIgnoreCase))return drive.Key+native.Substring(drive.Value.Length);
            return null;
        }
    }
    public sealed class ProcessIdentity {
        internal Func<string,bool> RuleName;
        readonly string desktop, code, packageRoot, legacyRoot;
        readonly EmbeddedCodePaths embedded;
        readonly Dictionary<string,string> drives = new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        readonly ConcurrentDictionary<string, Verified> images = new ConcurrentDictionary<string, Verified>(StringComparer.OrdinalIgnoreCase);
        sealed class Verified { public string Stamp, Kind, Version, Error = ""; public volatile int State = 2; }
        public ProcessIdentity(string desktop, string code) : this(desktop,code,Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) {}
        public ProcessIdentity(string desktop, string code, string ownerProfile) {
            this.desktop = CcIdentity.Normalize(desktop); this.code = CcIdentity.Normalize(code);
            embedded = new EmbeddedCodePaths(ownerProfile);
            foreach(string drive in Environment.GetLogicalDrives()) { var target=new StringBuilder(32768);string name=drive.TrimEnd('\\');if(QueryDosDevice(name,target,target.Capacity)!=0)drives[name]=target.ToString(); }
            string windowsApps = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),"WindowsApps") + "\\";
            if (this.desktop.StartsWith(windowsApps + AiCompatibility.S_c742c506fca927, StringComparison.OrdinalIgnoreCase) && this.desktop.EndsWith(AiCompatibility.S_396b68a6e842f8,StringComparison.OrdinalIgnoreCase)) packageRoot = windowsApps;
            string parent = Path.GetDirectoryName(this.desktop);
            if (Path.GetFileName(parent).StartsWith("app-",StringComparison.OrdinalIgnoreCase)) legacyRoot = Path.GetDirectoryName(parent) + "\\";
            VerifyInitial(this.desktop,"desktop"); VerifyInitial(this.code,"code");
            RefreshInstalled(true);
        }
        public static string ProfileForOwner(string sid) {
            var owner=new System.Security.Principal.SecurityIdentifier(sid);
            using(var key=Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\"+owner.Value)) {
                string profile=key==null?null:key.GetValue("ProfileImagePath") as string;
                if(string.IsNullOrWhiteSpace(profile)||!Path.IsPathRooted(profile)||profile.StartsWith(@"\\")||!Directory.Exists(profile))throw new IOException("Configured owner's Windows profile is unavailable.");
                return Path.GetFullPath(profile);
            }
        }
        static string Stamp(string path) { var info = new FileInfo(path); return info.Length + "/" + info.LastWriteTimeUtc.Ticks + "/" + info.CreationTimeUtc.Ticks; }
        string Kind(string path) {
            if (string.Equals(path,code,StringComparison.OrdinalIgnoreCase) || embedded.Matches(path)) return "code";
            if (string.Equals(path,desktop,StringComparison.OrdinalIgnoreCase) || packageRoot != null && path.StartsWith(packageRoot + AiCompatibility.S_c742c506fca927,StringComparison.OrdinalIgnoreCase) && path.EndsWith(AiCompatibility.S_396b68a6e842f8,StringComparison.OrdinalIgnoreCase) || legacyRoot != null && path.StartsWith(legacyRoot + "app-",StringComparison.OrdinalIgnoreCase) && path.EndsWith(AiCompatibility.S_cd0b1a0008d71c,StringComparison.OrdinalIgnoreCase)) return "desktop";
            return null;
        }
        void VerifyInitial(string path, string kind) { var entry = new Verified { Stamp = Stamp(path), Kind = kind }; Check(path,entry); if (entry.State != 1) throw new IOException(entry.Error); images[path] = entry; }
        public void RefreshInstalled() { RefreshInstalled(false); }
        void RefreshInstalled(bool synchronous) {
            foreach(string path in embedded.Installed())try {
                string stamp=Stamp(path);Verified old;
                if(images.TryGetValue(path,out old)&&old.Stamp==stamp)continue;
                var next=new Verified {Stamp=stamp,Kind="code"};
                bool added=old==null?images.TryAdd(path,next):images.TryUpdate(path,next,old);
                if(added) { if(synchronous)Check(path,next);else {string captured=path;Task.Run(()=>Check(captured,next));} }
            } catch(IOException) {} catch(UnauthorizedAccessException) {}
        }
        static void Check(string path, Verified entry) {
            try {
                // Prevent replacement during verification, then release the file
                // so official self-updates are not blocked by the network service.
                using (var file = new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)) {
                    if (!string.Equals(CcIdentity.FinalPath(file),path,StringComparison.OrdinalIgnoreCase) || Stamp(path) != entry.Stamp) throw new IOException(AiCompatibility.S_c9cba56aa3f28c);
                    var info = CcIdentity.Verify(path,entry.Kind); entry.Version = Convert.ToString(info["version"]); entry.State = 1;
                }
            } catch (Exception error) { entry.Error = error.Message; entry.State = 2; }
        }
        static string Image(uint pid,uint flags=0) { IntPtr p = OpenProcess(0x1000,false,pid); if (p == IntPtr.Zero) return null; try { var text = new StringBuilder(32768); uint size = (uint)text.Capacity; return QueryFullProcessImageName(p,flags,text,ref size) ? text.ToString() : null; } finally { CloseHandle(p); } }
        public int Select(uint pid) {
            if (pid == 4 || pid == 0) return 0;
            string path = Image(pid);
            if (path == null) { try { using (var p = Process.GetProcessById((int)pid)) {if(RuleName!=null&&RuleName(p.ProcessName))return 1;return p.ProcessName.Equals(AiCompatibility.S_c857d09db23e68,StringComparison.OrdinalIgnoreCase) ? 2 : 0;} } catch { return 0; } }
            if(RuleName!=null&&RuleName(Path.GetFileName(path)))return 1;
            string kind = Kind(path); if (kind == null) return 0;
            try {
                if(embedded.Matches(path)) {
                    // Win32 reports the virtual Roaming alias for Desktop's CC.
                    // The kernel image path identifies the actual opened EXE.
                    string actual=EmbeddedCodePaths.FromNative(Image(pid,1),drives);
                    if(!embedded.SameFileLocation(path,actual))return 2;
                    path=actual;
                }
                string stamp = Stamp(path); Verified entry;
                if (images.TryGetValue(path,out entry) && entry.Stamp == stamp) return entry.State;
                var next = new Verified { Stamp = stamp, Kind = kind };
                bool added = entry == null ? images.TryAdd(path,next) : images.TryUpdate(path,next,entry);
                if (added) Task.Run(() => Check(path,next));
                return 2;
            } catch { return 2; }
        }
        public object Status() { return images.Select(x => new { path = x.Key, kind = x.Value.Kind, version = x.Value.Version, signature_valid = x.Value.State == 1, error = x.Value.Error, desktop_embedded = embedded.Matches(x.Key), aliases = embedded.Aliases(x.Key) }).ToArray(); }
        // Include pending/invalid candidates so IPv6 cannot bypass verification.
        // Both the virtual and physical names need an application firewall rule.
        public string[] Paths { get { return images.Keys.SelectMany(path=>embedded.Aliases(path)).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(); } }
        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access,bool inherit,uint pid);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern bool QueryFullProcessImageName(IntPtr handle,uint flags,StringBuilder name,ref uint size);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint QueryDosDevice(string name,StringBuilder target,int capacity);
    }
}
