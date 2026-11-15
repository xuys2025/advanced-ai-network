using System;
using System.ComponentModel;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

// One SYSTEM writer. The stable file inherits the guard directory's ACL.
// Readers validate the record against the running service and its original lease.
internal sealed class GuardHeartbeat : IDisposable {
    const int Size=4096, Header=24, Schema=1;
    readonly MemoryMappedViewAccessor view;
    GuardHeartbeat(MemoryMappedViewAccessor accessor){view=accessor;}

    internal static GuardHeartbeat Open(string folder,bool writer){
        var access=writer?MemoryMappedFileAccess.ReadWrite:MemoryMappedFileAccess.Read;
        using(var file=new FileStream(Path.Combine(folder,"guard-heartbeat.bin"),
            writer?FileMode.OpenOrCreate:FileMode.Open,writer?FileAccess.ReadWrite:FileAccess.Read,
            writer?FileShare.Read:FileShare.ReadWrite)){
            if(writer && file.Length==0)file.SetLength(Size);
            if(file.Length!=Size)throw new InvalidDataException("Invalid guard heartbeat size.");
            using(var mapping=MemoryMappedFile.CreateFromFile(file,null,Size,access,HandleInheritability.None,true))
                return new GuardHeartbeat(mapping.CreateViewAccessor(0,Size,access));
        }
    }

    internal void Publish(int pid,string json){
        byte[] data=Encoding.UTF8.GetBytes(json);
        long writing=(view.ReadInt64(0)&~1L)+1;
        view.Write(0,writing);
        Thread.MemoryBarrier();
        if(data.Length>Size-Header)throw new InvalidDataException("Guard heartbeat too large.");
        view.Write(8,Schema);view.Write(12,pid);view.Write(16,data.Length);
        view.WriteArray(Header,data,0,data.Length);
        Thread.MemoryBarrier();
        view.Write(0,writing+1);
    }

    internal string Read(int pid){
        if(pid<=0)throw new IOException("Guard service is not running.");
        for(int attempt=0;attempt<4;attempt++){
            long before=view.ReadInt64(0);
            Thread.MemoryBarrier();
            if(before!=0 && (before&1)==0){
                int schema=view.ReadInt32(8),owner=view.ReadInt32(12),length=view.ReadInt32(16);
                if(length>0 && length<=Size-Header){
                    byte[] data=new byte[length];view.ReadArray(Header,data,0,length);
                    Thread.MemoryBarrier();
                    if(before==view.ReadInt64(0)){
                        if(schema!=Schema||owner!=pid)throw new InvalidDataException("Guard heartbeat service identity changed.");
                        return Encoding.UTF8.GetString(data);
                    }
                }
            }
            if(attempt<3)Thread.Sleep(1);
        }
        throw new IOException("Incomplete guard heartbeat.");
    }
    public void Dispose(){view.Dispose();}

    [DllImport("advapi32",CharSet=CharSet.Unicode)] static extern IntPtr OpenSCManager(string machine,string database,uint access);
    [DllImport("advapi32",CharSet=CharSet.Unicode)] static extern IntPtr OpenService(IntPtr manager,string name,uint access);
    [DllImport("advapi32")] static extern bool QueryServiceStatusEx(IntPtr service,int info,out ServiceStatus status,int size,out int needed);
    [DllImport("advapi32")] static extern bool CloseServiceHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] struct ServiceStatus {internal int type,state,controls,exit,specific,checkpoint,wait,pid,flags;}
    internal static int RunningPid(string name){
        IntPtr manager=OpenSCManager(null,null,1),service=IntPtr.Zero;
        try{
            if(manager==IntPtr.Zero || (service=OpenService(manager,name,4))==IntPtr.Zero)throw new IOException("Cannot open guard service.");
            ServiceStatus status;int needed;
            if(!QueryServiceStatusEx(service,0,out status,Marshal.SizeOf(typeof(ServiceStatus)),out needed))throw new IOException("Cannot query guard service.");
            return status.state==4?status.pid:0;
        }finally{if(service!=IntPtr.Zero)CloseServiceHandle(service);if(manager!=IntPtr.Zero)CloseServiceHandle(manager);}
    }

    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool MoveFileEx(string source,string target,int flags);
    internal static void WriteStatus(string path,string json){
        string temp=path+".tmp";
        File.WriteAllText(temp,json,new UTF8Encoding(false));
        if(!MoveFileEx(temp,path,1))throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
