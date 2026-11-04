'use strict';
const fs=require('node:fs');
const path=require('node:path');
function createLifecycle(directory,token=''){
  const marker=/^[0-9a-f]{32}$/.test(token)?path.join(directory,'exit-intent-'+token+'.json'):null;
  function log(message){
    const d=new Date(),pad=v=>String(v).padStart(2,'0');
    const stamp=`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    const clean=String(message).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/[\x00-\x1f\x7f-\x9f]/g,' ').slice(0,1400);
    try{fs.appendFileSync(path.join(directory,'runtime.log'),stamp+'  '+clean+'\r\n','utf8');}catch{}
  }
  function requestExit(reason){log('明确退出客户端：'+reason+'；域名保护保留。');if(marker)try{fs.writeFileSync(marker,JSON.stringify({requested_utc:new Date().toISOString()}),'utf8');}catch(error){log('无法保存退出标记：'+error.message);}}
  return {log,requestExit};
}
module.exports={createLifecycle};
