using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

internal static class GuardHeartbeatTests {
    static void Check(bool value,string message){if(!value)throw new Exception(message);}
    static void Reject(Action action){
        try{action();}catch(IOException){return;}catch(InvalidDataException){return;}
        throw new Exception("Invalid proof accepted.");
    }
    public static void Main(){
        string folder=Path.Combine(Path.GetTempPath(),"guard-proof-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        string json=Path.Combine(folder,"guard-status.json");
        try{
            Reject(()=>GuardHeartbeat.Open(folder,false));
            using(var writer=GuardHeartbeat.Open(folder,true))
            using(var reader=GuardHeartbeat.Open(folder,false)){
                Reject(()=>reader.Read(123));
                writer.Publish(123,"permitted");
                using(var blocked=new FileStream(json,FileMode.CreateNew,FileAccess.ReadWrite,FileShare.None)){
                    Check(reader.Read(123)=="permitted","Locked status file interrupted valid proof.");
                    writer.Publish(123,"revoked");
                    Check(reader.Read(123)=="revoked","Revocation lost.");
                    Reject(()=>reader.Read(124));Reject(()=>reader.Read(0));
                }
                GuardHeartbeat.WriteStatus(json,"first");GuardHeartbeat.WriteStatus(json,"second");
                Check(File.ReadAllText(json)=="second","Status rename failed.");
                string a=new string('a',301),b=new string('b',1703);
                writer.Publish(123,a);
                var changing=Task.Run(()=>{for(int i=0;i<500;i++){writer.Publish(123,i%2==0?b:a);Thread.Sleep(1);}});
                int coherent=0;
                do{
                    string proof;
                    try{proof=reader.Read(123);}catch(IOException){continue;}
                    Check(proof==a || proof==b,"Torn proof accepted.");coherent++;
                }while(!changing.IsCompleted);
                changing.GetAwaiter().GetResult();
                Check(coherent>0,"No coherent records read.");
            }
            using(var restarted=GuardHeartbeat.Open(folder,true))
            using(var reader=GuardHeartbeat.Open(folder,false)){
                Reject(()=>reader.Read(124));
                restarted.Publish(124,"closed");Check(reader.Read(124)=="closed","Restart failed.");
                Reject(()=>reader.Read(123));
            }
            File.WriteAllBytes(Path.Combine(folder,"guard-heartbeat.bin"),new byte[32]);
            Reject(()=>GuardHeartbeat.Open(folder,false));
            Console.WriteLine("PASS locked diagnostic JSON, immediate revocation, torn/missing records, service PID changes and restart.");
        }finally{foreach(string item in Directory.GetFiles(folder))File.Delete(item);Directory.Delete(folder);}
    }
}
