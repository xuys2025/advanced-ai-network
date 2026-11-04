using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using AdvancedAINetwork;
public static class GuardAnswerTests {
    static byte[] Query(string name,int type){var q=new List<byte>{1,2,1,0,0,1,0,0,0,0,0,0};foreach(string label in name.Split('.')){q.Add((byte)label.Length);q.AddRange(Encoding.ASCII.GetBytes(label));}q.AddRange(new byte[]{0,0,(byte)type,0,1});return q.ToArray();}
    public static int Main(){string scratch=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"guard-test-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(scratch);int count=0;using(var guard=new DomainGuard(scratch,selectiveTun:true)){
        foreach(string domain in Data.Roots.SelectMany(x=>new[]{x,"test."+x}).Concat(Data.Exact))foreach(int type in new[]{1,28,64,65}){byte[] q=Query(domain,type),a=guard.Answer(q);if(a==null||(a[3]&15)!=0)throw new Exception("DNS failure: "+domain);if(type==1){if(a[7]!=1||!GuardPolicy.Synthetic(new System.Net.IPAddress(a.Skip(a.Length-4).ToArray()).ToString()))throw new Exception("Invalid protected address");}else if(a.Skip(6).Take(6).Any(x=>x!=0))throw new Exception("Unexpected record");count++;}
        foreach(string name in new[]{"example.com",AiCompatibility.S_7cb0905114d852,AiCompatibility.S_e9d6b15983e3b5,"sub.api.ipify.org"}){if((guard.Answer(Query(name,1))[3]&15)!=5)throw new Exception("Scope regression");count++;}
        if(guard.Answer(new byte[]{1,2})!=null)throw new Exception("Short request accepted");count++;
    }Console.WriteLine("PASS "+count+" isolated domain guard checks");return 0;}
}
