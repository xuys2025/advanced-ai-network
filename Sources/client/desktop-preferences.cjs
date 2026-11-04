'use strict';
const fs=require('node:fs'),path=require('node:path');
const LOCAL_KEYS=['startMinimized','closeToTray'];
const ALL_KEYS=['appStartup',...LOCAL_KEYS];
function validatePreference(input){
  if(!input||typeof input!=='object'||Array.isArray(input))throw new Error('设置参数无效。');
  const keys=Object.keys(input);
  if(keys.length!==1||!ALL_KEYS.includes(keys[0])||typeof input[keys[0]]!=='boolean')throw new Error('每次只能保存一个有效的开关。');
  return {[keys[0]]:input[keys[0]]};
}
function shouldShowOnLaunch(args,preferences){return !args.includes('--startup')||!preferences.startMinimized;}
function createPreferences({app,directory,launcher,io=fs}){
  const file=path.join(directory,'desktop-ui-preferences.json');
  let local={startMinimized:true,closeToTray:true},startup=false,storageError='',startupError='';
  try{
    const value=JSON.parse(io.readFileSync(file,'utf8'));
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!LOCAL_KEYS.includes(k)||typeof value[k]!=='boolean'))throw new Error('文件内容无效');
    local={...local,...value};
  }catch(error){if(error.code!=='ENOENT')storageError='无法读取窗口偏好，请保留原文件并重试。';}
  const snapshot=()=>({...local,appStartup:startup,error:storageError||startupError});
  function refresh(){
    try{
      const result=app.getLoginItemSettings({path:launcher,args:['--startup']});
      startup=(result.launchItems||[]).some(item=>item.name==='AdvancedAIPrivateNetwork'&&item.scope==='user'&&item.enabled&&
        path.resolve(item.path.replace(/^"|"$/g,'')).toLowerCase()===path.resolve(launcher).toLowerCase());
      startupError='';
    }catch{startupError='无法读取 Windows 登录启动设置，请重试。';}
    return snapshot();
  }
  function update(input){
    const patch=validatePreference(input);
    if('appStartup' in patch){
      if(!app.isPackaged)throw new Error('请在已安装的客户端中修改登录自启动。');
      refresh();if(startupError)throw new Error(startupError);
      const previous=startup,enabled=patch.appStartup;
      try{
        app.setLoginItemSettings({name:'AdvancedAIPrivateNetwork',openAtLogin:enabled,enabled,path:launcher,args:['--startup']});
        refresh();if(startupError||startup!==enabled)throw new Error('Windows 未保存自启动设置，请重试。');
      }catch(error){
        try{app.setLoginItemSettings({name:'AdvancedAIPrivateNetwork',openAtLogin:previous,enabled:previous,path:launcher,args:['--startup']});refresh();}catch{}
        throw error;
      }
    }else{
      if(storageError)throw new Error(storageError);
      const next={...local,...patch},temporary=file+'.tmp';
      try{
        io.mkdirSync(directory,{recursive:true});
        io.writeFileSync(temporary,JSON.stringify(next,null,2),'utf8');
        io.renameSync(temporary,file);
        local=next;
      }catch{
        try{io.unlinkSync(temporary);}catch{}
        throw new Error('窗口偏好未能保存，原设置已保留。');
      }
    }
    return snapshot();
  }
  refresh();
  return Object.freeze({current:snapshot,refresh,update});
}
module.exports={createPreferences,validatePreference,shouldShowOnLaunch};
