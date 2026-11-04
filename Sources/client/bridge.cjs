'use strict';
const { spawn } = require('node:child_process');
const { EventEmitter } = require('node:events');
const readline = require('node:readline');
const path=require('node:path');
const lifecycle=require('./lifecycle.cjs').createLifecycle(path.join(process.env.LOCALAPPDATA,'AdvancedAIPrivateNetwork'));
class NativeBridge extends EventEmitter {
  constructor(executable) { super(); this.executable = executable; this.pending = new Map(); this.sequence = 0; this.stopping = false; this.child = null; this.failures = 0; }
  start() {
    if (this.stopping) return;
    this.child = spawn(this.executable, [String(process.pid)], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    const child = this.child;
    readline.createInterface({ input: child.stdout }).on('line', line => {
      try {
        const message = JSON.parse(line);
        if (message.id && this.pending.has(message.id)) { const call = this.pending.get(message.id); this.pending.delete(message.id); clearTimeout(call.timer); message.ok ? call.resolve(message.result) : call.reject(new Error(message.error || '操作未完成')); }
        if (message.event === 'state') { this.failures = 0; this.emit('state', message.state); }
        if (message.event === 'log') this.emit('log', message.entry);
        if (message.event === 'fatal') this.emit('fault', message.error);
      } catch { this.emit('fault', '本机控制器输出无效，原有保护仍保留。'); }
    });
    child.stderr.on('data', () => {});
    child.stdin.on('error', () => {});
    child.on('error', error => this.emit('fault', '无法启动本机控制器：' + error.message));
    child.on('close', (code,signal) => {
      if (this.child !== child) return;
      lifecycle.log('本机控制器结束：退出码='+code+'，信号='+(signal||'无')+'，主动关闭='+this.stopping+'。');
      for (const call of this.pending.values()) { clearTimeout(call.timer); call.reject(new Error('控制器正在恢复，原有保护保留。')); }
      this.pending.clear();
      if (!this.stopping) { this.emit('fault', '本机控制器已退出，正在恢复；保护规则持续保留。'); const delay = Math.min(30000, 1000 * 2 ** Math.min(this.failures++, 5)); this.restart = setTimeout(() => this.start(), delay); }
    });
    this.ping && clearInterval(this.ping);
    this.ping = setInterval(() => { if (this.child && !this.child.killed && this.child.stdin.writable) this.child.stdin.write(JSON.stringify({ method: 'heartbeat' }) + '\n'); }, 2500);
  }
  request(method, params = {}) {
    if (!this.child || this.child.killed || !this.child.stdin.writable) return Promise.reject(new Error('本机控制器暂不可用，保护仍保留。'));
    const id = String(++this.sequence);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error('操作响应超时，请查看页面进度；已有保护保留。')); }, 20000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n', error => { if (error && this.pending.has(id)) { clearTimeout(timer); this.pending.delete(id); reject(new Error('控制器连接已中断。')); } });
    });
  }
  async close() {
    this.stopping = true; clearTimeout(this.restart); clearInterval(this.ping);
    const child = this.child;
    if (!child || child.exitCode !== null) return;
    try { await this.request('shutdown'); } catch {}
    await Promise.race([new Promise(resolve => child.once('exit', resolve)), new Promise(resolve => setTimeout(resolve, 2500))]);
    if (child.exitCode === null) child.kill();
  }
}
module.exports = { NativeBridge };
