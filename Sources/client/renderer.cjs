'use strict';
function displayValue(value){return String(value??'').replace(new RegExp(AICompat.TargetProductWord,'gi'),'高级 AI').replace(new RegExp(AICompat.TargetCompanyWord,'gi'),'高级公司');}
const $=id=>document.getElementById(id),text=(id,value)=>$(id).textContent=displayValue(value);
let state={},pending=false,initialized=false,programKey='',protectionKey='',toastTimer;
let preferencePending=false,preferenceFeedback='更改后自动保存，下次打开时继续生效。';
const pages={overview:['连接概览','专用流量有专用出口，其余连接保持原样。'],network:['出口设置','选择你的局域网出口，先验证，再切换。'],protection:['保护状态','查看仍在生效的保护，以及它们的覆盖范围。'],diagnostics:['运行诊断','了解当前连接，保留可核查的运行信息。'],preferences:['偏好设置','按你的习惯设置登录启动与窗口常驻。']};
function navigate(page){if(!pages[page])return;for(const key of Object.keys(pages))$('page-'+key).hidden=key!==page;for(const b of document.querySelectorAll('.nav')){b.classList.toggle('active',b.dataset.page===page);if(b.dataset.page===page)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}text('page-title',pages[page][0]);text('page-description',pages[page][1]);document.querySelector('main').scrollTop=0;if(page==='preferences')window.gateway.readPreferences().then(render).catch(error=>notify(error.message));}
for(const button of document.querySelectorAll('[data-page]'))button.onclick=()=>navigate(button.dataset.page);
function node(tag,cls,value){const el=document.createElement(tag);if(cls)el.className=cls;if(value!==undefined)el.textContent=displayValue(value);return el;}
function icon(name,cls){const wrap=node('div',cls);const svg=document.createElementNS('http://www.w3.org/2000/svg','svg'),use=document.createElementNS(svg.namespaceURI,'use');use.setAttribute('href','#i-'+name);svg.append(use);wrap.append(svg);return wrap;}
function pill(id,value,ok){text(id,value);$(id).className='pill '+(ok?'good':'warn');}
function size(value){let n=Number(value)||0,i=0;const units=['B','KB','MB','GB'];while(n>=1024&&i<3){n/=1024;i++;}return n.toFixed(i?1:0)+' '+units[i];}
function at(value){return value?new Date(value).toLocaleTimeString('zh-CN',{hour12:false}):'尚未验证';}
function notify(value){text('toast',value);$('toast').hidden=false;clearTimeout(toastTimer);toastTimer=setTimeout(()=>$('toast').hidden=true,6500);}
function renderPrograms(s){const identities=s.identities||[],key=JSON.stringify([identities,!!s.capturing,!!s.stale]);if(key===programKey)return;programKey=key;const cards=identities.length?identities:[{kind:'desktop'},{kind:'code'}];$('programs').replaceChildren(...cards.map(p=>{const card=node('article','card program'),copy=node('div');copy.append(node('h3','',p.kind==='code'?'高级 AI CLI':'高级 AI 桌面端'),node('div','program-version',p.version?'v'+p.version:'正在核实程序'));card.append(icon(p.kind==='code'?'terminal':'desktop','icon-tile'),copy);card.title=displayValue(p.path||'');const foot=node('div','program-bottom');foot.append(node('span','',s.capturing&&!s.stale?'TCP / UDP 分流已启用':'等待后台分流'),node('span','pill '+(p.signature_valid?'good':'warn'),p.signature_valid?'官方签名已核实':'等待签名核实'));card.append(foot);return card;}));}
function renderProtection(s){const fresh=!s.stale,guard=s.guard||{},safe=fresh&&!!s.guard_protected;
  const rows=[['域名保护与独立守护',safe,'清单域名使用专用解析与连接，界面退出后继续生效。'],['DNS 绕行防护',fresh&&!!(guard.dns_64_65_blocked??s.dns64_65_blocked),'屏蔽清单域名的 HTTPS / SVCB 记录；IPv6 解析不返回地址。'],['受保护地址防泄漏',fresh&&!!(guard.network_safety_ready??s.guard_protected),'受保护地址不能经物理网卡直连，TUN 异常时保留阻断。'],['主程序分流与 IPv6 阻断',fresh&&!!s.capturing&&!!s.ipv6_firewall_ready,'清单程序与已验证的 Desktop、CLI 使用专用出口。']];
  const key=JSON.stringify(rows);if(key!==protectionKey){protectionKey=key;$('protection-checks').replaceChildren(...rows.map(([title,ok,description])=>{const row=node('div','protection-row'),copy=node('div');copy.append(node('strong','',title),node('p','',description));row.append(icon(ok?'check':'pulse','check-icon'+(ok?'':' warn')),copy,node('span','pill '+(ok?'good':'warn'),ok?'生效中':'待确认'));return row;}));}
  text('guard-summary',safe?'域名保护运行中':'保护状态待确认');const all=rows.every(r=>r[1]);text('protection-heading',all?'原有保护仍在生效':'部分保护状态需要确认');pill('protection-badge',all?'保护正常':'待确认',all);
}
function renderOperation(){const op=state.gateway_operation||{},busy=pending||['validating','applying'].includes(op.phase),input=$('gateway-input').value.trim(),match=op.gateway===input;
  $('validate').disabled=busy||state.stale||!state.gateway;$('gateway-input').disabled=op.phase==='applying';text('validate',op.phase==='validating'?'正在验证…':'验证出口');
  $('apply').disabled=busy||state.stale||op.phase!=='validated'||!match||new Date(op.expires_utc).getTime()<=Date.now();
  const box=$('validation-result');box.className='validation muted';let title='',detail='先验证网关，确认实际公网出口后即可保存。';
  if(op.phase==='validating'){title='正在验证 '+op.gateway;detail='检查网关连接、DNS 和 HTTPS，当前出口继续运行。';}
  else if(op.phase==='applying'){title='正在切换出口';detail='正在保存设置并恢复专用连接…';}
  else if(op.phase==='validated'&&match){box.className='validation good';title='验证通过 · '+op.gateway;detail='公网 IP '+op.exit?.ip+' · '+[op.exit?.loc,op.exit?.colo].filter(Boolean).join(' / ')+'。确认此出口后，点击「保存并使用」。';}
  else if(op.phase==='applied'&&match){box.className='validation good';title='已保存并使用 '+op.gateway;detail='专用流量已使用此网关，设置将在后台重启后保留。';}
  else if(op.phase==='failed'&&(match||!op.gateway)){box.className='validation warn';title='未更改当前出口';detail=op.message||'请检查网关后重试。';}
  else if(op.phase==='expired'){detail='验证结果已过期，请重新验证后保存。';}
  box.replaceChildren();if(title)box.append(node('strong','',title));box.append(node('span','',detail));
  $('check').disabled=busy||state.stale||!state.gateway;$('toggle').disabled=busy||state.stale||!state.gateway;
  text('check-result',op.phase==='checked'?'检查通过 · '+op.exit?.ip+' · '+at(op.checked_utc):op.phase==='validating'?'正在检查出口…':op.phase==='failed'?op.message:'');
}
function render(s){state=s;renderFeed(s);const ready=!!s.ready,paused=s.enabled===false;
  document.body.dataset.connectionState=s.stale?'stale':paused?'paused':ready?'ready':'loading';
  text('backend-release',s.version?'v'+s.version.replace(/-lan\.\d+$/,''):'—');
  renderPreferences();
  pill('top-status',ready?'●  专用出口已连接':paused?'连接已暂停':'等待后台就绪',ready);text('heading',ready?'连接就绪，安心使用':paused?'专用连接已暂停':'正在等待出口就绪');text('hero-description',ready?'命中网址、IPv4 网段、ASN 或程序名的流量走专用出口。':s.message||'正在读取后台状态…');text('hero-label',ready?'局域网专用出口 · 运行中':'局域网专用出口');text('toggle',paused?'恢复连接':'暂停连接');
  text('gateway',s.gateway||'—');text('public-ip',s.last_exit||'—');text('nic-summary',(s.adapter_name||'以太网')+' · '+(s.local_ip||'等待本机地址'));text('exit-location',[s.exit_location,s.exit_colo].filter(Boolean).join(' / ')+(s.exit_verified_utc?' · '+at(s.exit_verified_utc)+' 验证':''));
  text('settings-adapter',s.adapter_name||'以太网');text('settings-local',s.local_ip||'—');text('settings-current',s.gateway||'—');if(!initialized&&s.gateway){$('gateway-input').value=s.gateway;initialized=true;}
  const proxies=[s.domain_proxy,s.clash_proxy].filter(Boolean),up=proxies.reduce((n,p)=>n+(Number(p.upload)||0),0),down=proxies.reduce((n,p)=>n+(Number(p.download)||0),0);text('traffic-total',size(up+down));text('traffic-detail','↑ '+size(up)+'  ·  ↓ '+size(down));renderPrograms(s);renderProtection(s);renderOperation();
  const values=[['后台版本',s.version||'—'],['运行状态',s.stale?'状态已过期':ready?'已连接':paused?'已暂停':'等待就绪'],['当前出口',s.gateway||'—'],['公网 IP',s.last_exit||'—'],['最近出口验证',s.exit_verified_utc?new Date(s.exit_verified_utc).toLocaleString('zh-CN',{hour12:false}):'—'],['系统代理兼容','保留 Clash · 本机端口 '+(s.front_port||'—')],['后台心跳',at(s.updated_utc)]];$('diagnostic-summary').replaceChildren(...values.flatMap(([key,value])=>[node('dt','',key),node('dd','',value)]));text('raw-state',JSON.stringify(s,null,2));
}
async function action(name,params){pending=true;renderOperation();try{render(await window.gateway.action(name,params));}catch(error){notify(error.message);}finally{pending=false;renderOperation();}}
$('gateway-input').addEventListener('input',renderOperation);
$('gateway-form').onsubmit=event=>{event.preventDefault();const gateway=$('gateway-input').value.trim();if(!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(gateway)||gateway.split('.').some(x=>Number(x)>255)){notify('请输入完整的 IPv4 地址，例如 192.168.1.254。');return;}action('gateway:validate',{gateway});};
$('apply').onclick=()=>{if(!$('apply').disabled)action('gateway:apply',{token:state.gateway_operation.token});};
$('toggle').onclick=()=>action(state.enabled===false?'connect':'disconnect');$('check').onclick=()=>action('check');
let displayedRevision='';
function renderFeed(s){
  const f=s.rule_sync||{},p=f.policy||{},busy=!!(f.busy||f.requested),valid=!!p.revision&&!s.stale;
  pill('feed-badge',busy?'正在检查':valid?'规则已载入':'等候后台',valid);
  text('feed-message',f.message||'通过专用网关下载并校验规则。');
  text('feed-outlet',s.gateway||'—');
  text('feed-time',f.last_success?new Date(f.last_success).toLocaleString('zh-CN',{hour12:false}):'等待首次验证');
  text('feed-revision',(p.sha256||'').slice(0,12)||'—');text('feed-url',f.source||'');
  $('feed-auto').checked=!!f.automatic;$('feed-auto').disabled=pending||!valid;
  $('feed-refresh').disabled=pending||busy||!valid||!s.ready;
  if(!p.revision||displayedRevision===p.revision)return;displayedRevision=p.revision;
  text('feed-ip',p.ipv4.join('、')||'无');text('feed-asn',p.asns.map(n=>'AS'+n).join('、')||'无');
  text('feed-announced',p.announced.join('、')||'无 IPv4 公告');text('feed-processes',p.processes.join('、')||'无');
  text('feed-domain-count','网址清单 · '+p.roots.length+' 组域名 / '+p.exact.length+' 个指定地址 / '+p.keywords.length+' 个关键词');
  $('domain-list').replaceChildren(...p.roots.map(x=>node('span','',x+' + 子域名')),...p.exact.map(x=>node('span','exact',x)),...p.keywords.map(x=>node('span','','名字含 '+x)));
}
$('feed-refresh').onclick=()=>action('rules:refresh');
$('feed-auto').onchange=()=>action($('feed-auto').checked?'rules:auto-on':'rules:auto-off');

window.gateway.onState(render);window.gateway.state().then(render).catch(error=>notify(error.message));
function renderPreferences(){
  const p=state.desktop_preferences;
  for(const el of document.querySelectorAll('[data-preference]')){el.checked=!!p?.[el.dataset.preference];el.disabled=preferencePending||!p||!!p.error;}
  for(const el of document.querySelectorAll('[data-preference-status]'))el.textContent=!p?'读取中':p[el.dataset.preferenceStatus]?'已开启':'已关闭';
  text('preferences-result',preferencePending?'正在保存…':p?.error||(!p?'正在读取当前设置…':preferenceFeedback));
  text('preferences-connection',state.stale?'状态待确认':state.enabled===false?'已暂停':state.ready?'运行中':'等待就绪');
  $('preferences-connection').className='pill '+(!state.stale&&state.ready?'good':'muted');
}
for(const el of document.querySelectorAll('[data-preference]'))el.addEventListener('change',async()=>{
  const patch={[el.dataset.preference]:el.checked};preferencePending=true;renderPreferences();
  try{render(await window.gateway.savePreferences(patch));preferenceFeedback='偏好已保存，下次打开时继续生效。';}
  catch(error){preferenceFeedback='未能保存：'+error.message;notify(error.message);try{render(await window.gateway.readPreferences());}catch{}}
  finally{preferencePending=false;renderPreferences();}
});
