'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const raw = fs.readFileSync(path.join(__dirname, 'values.json'), 'utf8');
const encoded = JSON.parse(raw);
const digest = crypto.createHash('sha256').update(raw).digest('hex');
const values = Object.fromEntries(Object.entries(encoded).map(([key, value]) => [key, Buffer.from(value, 'base64').toString('utf8')]));
const constants = Object.entries(values).filter(([key]) => key.startsWith('S_') || key.endsWith('Word'));
const escaped = value => Array.from({length:value.length}, (_, i) => '\\u' + value.charCodeAt(i).toString(16).padStart(4, '0')).join('');
const header = '// Generated from compatibility/values.json. SHA256 ' + digest + '\n';
function write(relative, content) {
  const file = path.join(root, relative);
  fs.mkdirSync(path.dirname(file), {recursive:true});
  fs.writeFileSync(file, content);
}
const cs = header + 'internal static class AiCompatibility {\n' + constants.map(([key,value]) => '    internal const string ' + key + ' = "' + escaped(value) + '";').join('\n') + '\n}\n';
write('compatibility/Compatibility.cs', cs);
const js = 'Object.freeze({\n' + constants.map(([key,value]) => '  ' + key + ': "' + escaped(value) + '"').join(',\n') + '\n})';
write('compatibility/values.cjs', header + 'module.exports = ' + js + ';\n');
write('Sources/client/compatibility.cjs', header + 'module.exports = ' + js + ';\n');
write('Sources/client/compatibility-browser.js', header + 'const AICompat = ' + js + ';\n');
const powershell = '# Generated from compatibility/values.json. SHA256 ' + digest + '\n' +
  '$script:AiCompatibilityValues = @{\n' + Object.entries(encoded).map(([key,value]) => "    '" + key + "' = '" + value + "'").join('\n') + '\n}\n' +
  'function Get-AiCompatibility([string]$Key) {\n' +
  "    if (!$script:AiCompatibilityValues.ContainsKey($Key)) { throw 'Unknown compatibility key.' }\n" +
  '    return [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($script:AiCompatibilityValues[$Key]))\n}\n';
write('compatibility/Runtime.ps1', powershell);
write('Guard/compatibility/Runtime.ps1', powershell);
const c = header + '#ifndef AI_COMPATIBILITY_H\n#define AI_COMPATIBILITY_H\n' + constants.map(([key,value]) => '#define AI_COMPAT_' + key + ' "' + [...Buffer.from(value)].map(b => '\\' + b.toString(8).padStart(3, '0')).join('') + '"').join('\n') + '\n#endif\n';
write('compatibility/ai_compatibility.h', c);
const clashFile = path.join(root, 'Clash-Rules.js');
const clash = fs.readFileSync(clashFile, 'utf8');
const inline = '// AI_COMPAT_BEGIN\n' + header + 'const AICompat = ' + js + ';\n// AI_COMPAT_END';
const updated = clash.includes('// AI_COMPAT_INLINE') ? clash.replace('// AI_COMPAT_INLINE',inline) : clash.replace(/\/\/ AI_COMPAT_BEGIN[\s\S]*?\/\/ AI_COMPAT_END/,inline);
if (!updated.includes('// AI_COMPAT_BEGIN')) throw Error('Clash compatibility marker is missing.');
fs.writeFileSync(clashFile, updated);
console.log('Generated compatibility constants and runtime helpers.');
