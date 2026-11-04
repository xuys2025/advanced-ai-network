using System;
using System.Collections.Generic;
using System.IO;
using AdvancedAINetwork;
using AdvancedAINetwork.Gateway;

public static class IdentityPathTests {
    static int checks;
    static void Require(bool condition,string message) { if(!condition)throw new Exception(message);checks++; }
    public static int Main() {
        const string profile=@"C:\Users\fixture";
        var paths=new EmbeddedCodePaths(profile);
        string roaming=profile+AiCompatibility.S_261e578828f76c;
        string packaged=profile+AiCompatibility.S_595db57e5a9b4b;
        string suffix=AiCompatibility.S_36baced9cafa91;
        foreach(string root in new[]{roaming,packaged}) {
            foreach(string version in new[]{"2.1.309","2.1.310","3.0.0-beta.1","3.0.0+build.2"}) {
                string path=root+version+AiCompatibility.S_fca1ce0f9b8419;
                Require(paths.Matches(path),"Official version rejected");
                Require(paths.Matches(path.ToUpperInvariant()),"Case handling failed");
            }
            foreach(string suffixBad in new[]{AiCompatibility.S_398d1f3ec4fbc5,AiCompatibility.S_d2c017a4701c32,AiCompatibility.S_84ac3cf040d21f,@"2.1.309\9078b9c1d466\node.exe",AiCompatibility.S_807b03884ec0d0,AiCompatibility.S_5e49ba02d862bd,AiCompatibility.S_378a3b58ec3728,AiCompatibility.S_52494c85679037,AiCompatibility.S_097cfee28688ac})
                Require(!paths.Matches(root+suffixBad),"Unsafe descendant accepted: "+suffixBad);
        }
        foreach(string bad in new[]{null,"","a",@"C:",roaming.Replace("fixture","other")+suffix,packaged.Replace("pzs8sxrjxfjjc","otherpublisher")+suffix,roaming.Replace(AiCompatibility.S_de16635ea86e5c,AiCompatibility.S_1d50cbb437f528)+suffix,roaming.Replace(AiCompatibility.S_6696e7eff47b38,AiCompatibility.S_f193efdff93b56)+suffix,roaming+suffix+"\n",(roaming+suffix).Replace('\\','/'),@"\\server\share\"+suffix})
            Require(!paths.Matches(bad),"Outside path accepted");
        Require(paths.SameFileLocation(roaming+suffix,packaged+suffix),"MSIX alias rejected");
        Require(!paths.SameFileLocation(roaming+suffix,packaged+suffix.Replace("309","310")),"Wrong version alias accepted");
        Require(!paths.SameFileLocation(roaming+suffix,packaged+suffix.Replace("9078","aaaa")),"Wrong build alias accepted");
        Require(!paths.SameFileLocation(roaming+suffix,null),"Missing kernel path accepted");
        Require(paths.Aliases(packaged+suffix).Length==2,"Both firewall names required");
        var drives=new Dictionary<string,string>{{"C:",@"\Device\HarddiskVolume3"},{"D:",@"\Device\HarddiskVolume30"}};
        Require(EmbeddedCodePaths.FromNative(@"\Device\HarddiskVolume3"+(packaged+suffix).Substring(2),drives)==packaged+suffix,"Physical path conversion failed");
        Require(EmbeddedCodePaths.FromNative(AiCompatibility.S_92e26389d20d72,drives)==AiCompatibility.S_c27f3a47c4da64,"Device prefix boundary failed");
        Require(EmbeddedCodePaths.FromNative(AiCompatibility.S_6511a3c13b05b2,drives)==null,"Unknown device accepted");
        Require(EmbeddedCodePaths.FromNative(AiCompatibility.S_067608e03442e3,drives)==null,"Network executable accepted");
        bool rejected=false;try{CcIdentity.Verify(System.Reflection.Assembly.GetExecutingAssembly().Location);}catch{rejected=true;}
        Require(rejected,"Unsigned executable passed official signature validation");
        Console.WriteLine("PASS "+checks+AiCompatibility.S_1d0ba02db11413);return 0;
    }
}
