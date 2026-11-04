'use strict';
const {contextBridge,ipcRenderer}=require('electron');
contextBridge.exposeInMainWorld('gateway',{state:()=>ipcRenderer.invoke('state'),action:(name,params={})=>ipcRenderer.invoke('action',name,params),onState:fn=>ipcRenderer.on('state',(_e,state)=>fn(state)),readPreferences:()=>ipcRenderer.invoke('preferences:read'),savePreferences:patch=>ipcRenderer.invoke('preferences:save',patch)});
