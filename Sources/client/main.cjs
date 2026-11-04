'use strict';
const {app,BrowserWindow,ipcMain,Tray,Menu,nativeImage}=require('electron');
const path=require('node:path');
const fs=require('node:fs');
const AICompat=require('./compatibility.cjs');
const displayValue=value=>String(value??'').replace(new RegExp(AICompat.TargetProductWord,'gi'),'高级 AI').replace(new RegExp(AICompat.TargetCompanyWord,'gi'),'高级公司');
const {NativeBridge}=require('./bridge.cjs');
const {createPreferences,shouldShowOnLaunch}=require('./desktop-preferences.cjs');
const tokenAt=process.argv.indexOf('--launch-token');
const lifecycle=require('./lifecycle.cjs').createLifecycle(path.join(process.env.LOCALAPPDATA,'AdvancedAIPrivateNetwork'),tokenAt>=0?process.argv[tokenAt+1]:'');
let window,tray,bridge,quitting=false,state={ready:false,message:'正在读取后台状态…'};
let preferences;
function quitInterface(reason){lifecycle.requestExit(reason);quitting=true;app.quit();}
function restore(){if(window&&!window.isDestroyed()){if(window.isMinimized())window.restore();window.show();window.focus();}}
const testAt=process.argv.indexOf('--self-test');
if(testAt>=0)app.setPath('userData',process.argv[testAt+1]+'.profile');
if(!app.requestSingleInstanceLock())app.quit();
else {
  app.on('second-instance',restore);
  app.whenReady().then(()=>{
    preferences=createPreferences({app,directory:path.join(process.env.LOCALAPPDATA,'AdvancedAIPrivateNetwork'),launcher:path.join(path.dirname(process.execPath),'AdvancedAINetworkLauncher.exe')});
    window=new BrowserWindow({width:1200,height:850,minWidth:1000,minHeight:740,show:false,backgroundColor:'#f6f8f6',title:'高级 AI 专用网络',webPreferences:{preload:path.join(__dirname,'preload.cjs'),contextIsolation:true,nodeIntegration:false,sandbox:true}});
    Menu.setApplicationMenu(null);
    window.webContents.setWindowOpenHandler(()=>({action:'deny'}));
    window.webContents.on('will-navigate',e=>e.preventDefault());
    window.webContents.session.setPermissionRequestHandler((_w,_p,callback)=>callback(false));
    window.on('close',e=>{if(!quitting){e.preventDefault();if(preferences.current().closeToTray)window.hide();else quitInterface('用户关闭窗口，已关闭留在托盘选项');}});
    window.loadFile(path.join(__dirname,'index.html'));
    window.once('ready-to-show',()=>{if(testAt<0&&shouldShowOnLaunch(process.argv,preferences.current()))window.show();});
    const icon=nativeImage.createFromPath(path.join(__dirname,'icon.png'));tray=new Tray(icon);
    tray.setContextMenu(Menu.buildFromTemplate([{label:'打开 高级 AI 专用网络',click:restore},{type:'separator'},{label:'退出界面（后台继续运行）',click:()=>quitInterface('用户退出局域网出口界面')}]));tray.on('double-click',restore);
    bridge=new NativeBridge(path.join(process.resourcesPath,'native','AdvancedAINetworkAgent.exe'));
    const publish=value=>{state={...value,desktop_preferences:preferences.current()};if(!window.isDestroyed())window.webContents.send('state',state);tray.setToolTip('高级 AI 专用网络 · '+(state.ready?'局域网出口已连接':'等待连接'));try{if(testAt>=0)return;const file=path.join(process.env.LOCALAPPDATA,'AdvancedAIPrivateNetwork','runtime-status.json'),temp=file+'.lan.tmp';fs.writeFileSync(temp,JSON.stringify({...state,connected:!!state.ready,verified_ingress:!!state.ready,pid:process.pid,agent_pid:bridge.child?.pid,updated_utc:new Date().toISOString()}));fs.renameSync(temp,file);}catch{}};
    window.on('focus',()=>{preferences.refresh();publish(state);});
    bridge.on('state',publish);bridge.on('fault',error=>publish({...state,ready:false,message:error}));bridge.start();
    if(testAt>=0){
      const output=process.argv[testAt+1];
      setTimeout(async()=>{
        try{
          const views=[];
          for(const page of ['overview','network','protection','diagnostics']){
            await window.webContents.executeJavaScript('document.querySelector(".nav[data-page='+page+']").click()');
            await new Promise(resolve=>setTimeout(resolve,150));
            const dom=await window.webContents.executeJavaScript('({page:document.getElementById("page-title").textContent,programs:document.querySelectorAll(".program").length,overflow:document.querySelector("main").scrollWidth>document.querySelector("main").clientWidth})');
            if(page==='protection'){
              dom.feed=await window.webContents.executeJavaScript('({source:document.getElementById("feed-url").textContent,enabled:document.getElementById("feed-auto").checked,asn:document.getElementById("feed-asn").textContent,processes:document.getElementById("feed-processes").textContent})');
              if(process.argv.includes('--check-rule-button')){
                const before=state.rule_sync.last_success;
                await window.webContents.executeJavaScript('document.getElementById("feed-refresh").click()');
                const until=Date.now()+45000;
                while(state.rule_sync.last_success===before&&Date.now()<until)await new Promise(resolve=>setTimeout(resolve,250));
                if(state.rule_sync.last_success===before)throw Error('The refresh button did not complete an update.');
                dom.button_verified=true;
              }
            }
            const picture=await window.webContents.capturePage();
            fs.writeFileSync(output+'.'+page+'.png',picture.toPNG());views.push(dom);
          }
          const feed=views[2].feed;
          const success=views.every(x=>x.programs>=2&&!x.overflow)&&state.ready&&feed.source===displayValue(state.rule_sync.source)&&feed.enabled===state.rule_sync.automatic&&feed.asn===(state.rule_sync.policy.asns.map(n=>'AS'+n).join('、')||'无');
          fs.writeFileSync(output,JSON.stringify({success,views,state}));
        }catch(error){fs.writeFileSync(output,JSON.stringify({success:false,error:error.message}));}
        finally{quitting=true;await bridge.close();app.exit(0);}
      },3500);
    }
    ipcMain.handle('state',event=>{trusted(event);return {...state,desktop_preferences:preferences.current()};});
    ipcMain.handle('preferences:read',event=>{trusted(event);preferences.refresh();publish(state);return state;});
    ipcMain.handle('preferences:save',(event,patch)=>{trusted(event);try{preferences.update(patch);}finally{publish(state);}return state;});
    ipcMain.handle('action',async(event,name,params={})=>{trusted(event);if(!['connect','disconnect','check','gateway:validate','gateway:apply','rules:refresh','rules:auto-on','rules:auto-off'].includes(name))throw new Error('不支持的操作');if(name.startsWith('gateway:')){const key=name==='gateway:validate'?'gateway':'token';if(!params||typeof params[key]!=='string'||params[key].length>64)throw new Error('无效的出口参数');params={[key]:params[key]};}else params={};return bridge.request(name,params);});
    function trusted(event){if(event.sender!==window.webContents||event.senderFrame!==window.webContents.mainFrame)throw new Error('无效的界面来源');}
  });
  app.on('before-quit',()=>{quitting=true;bridge?.close();});
  app.on('window-all-closed',()=>{});
}
