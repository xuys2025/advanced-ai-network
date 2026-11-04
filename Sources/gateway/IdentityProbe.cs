using System;
using System.Web.Script.Serialization;
using AdvancedAINetwork.Gateway;
public static class IdentityProbe {
    public static int Main(string[] args){try{var identity=new ProcessIdentity(args[0],args[1]);Console.WriteLine(new JavaScriptSerializer().Serialize(identity.Status()));return 0;}catch(Exception error){Console.Error.WriteLine(error.Message);return 1;}}
}
