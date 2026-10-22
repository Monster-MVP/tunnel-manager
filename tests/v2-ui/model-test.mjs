/** Independent UI review of the model-call workflow against the owned synthetic fixture. */
import { chromium } from 'playwright';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { expect } from '@playwright/test';
import { contrast, viewports } from '../../scripts/v2-ui-audit.mjs';

const root = process.cwd();
const metadataPath = path.resolve(process.argv[2] || 'var/reports/codex-model-ui-fixture-r1.json');
const out = path.resolve(process.argv[3] || 'var/reports/codex-model-ui-final-r1');
if (!metadataPath.startsWith(root + path.sep) || !out.startsWith(root + path.sep)) throw new Error('project-local paths required');
if (fs.existsSync(out)) throw new Error('preserve prior evidence; use a fresh output directory');
const fixture = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
if (!fixture.evidence?.synthetic_credentials || fixture.evidence.genuine_provider_verified || !fixture.ipc_socket.startsWith(root)) throw new Error('synthetic owned fixture required');
fs.mkdirSync(out, { recursive: true, mode: 0o700 });

function rpc(socketPath, command) { return new Promise((resolve, reject) => {
  const socket = net.createConnection(socketPath); let body = ''; socket.setTimeout(5000);
  socket.on('connect', () => socket.write(JSON.stringify(command) + '\n'));
  socket.on('data', chunk => { body += chunk; if (body.includes('\n')) { socket.end(); try { resolve(JSON.parse(body.trim())); } catch (e) { reject(e); } } });
  socket.on('error', reject); socket.on('end', () => { if (!body.includes('\n')) reject(new Error('fixture IPC closed without result')); }); socket.on('timeout', () => { socket.destroy(); reject(new Error('fixture IPC timeout')); });
}); }
const evidence = { status: 'IN_PROGRESS', started_at:new Date().toISOString(), candidate:fixture.packaged_app, baseline:'var/reports/codex-credentials-ui-final-r3/light-1440x900-readable.png', baseline_manually_viewed:true, fixture: fixture.evidence, mocked_responses: false, production_services_controlled: false, personal_credentials_read: false, genuine_provider_verified:false, screenshots: [], checks: [], failures: [], assets:[], model_api_calls:0, preview_api_calls:0 };
const cases = ['responses','chat','auth','permission','rate','model','html','empty','incomplete','credential','tls','dns'];
const labels = { responses:'已验证模型可调用', chat:'已验证模型可调用', auth:'API 密钥鉴权失败', permission:'服务拒绝访问', rate:'额度或速率限制', model:'模型不可用', html:'服务响应格式不符', empty:'没有返回生成文本', incomplete:'模型生成未完成', credential:'API 密钥不可用', tls:'TLS 证书验证失败', dns:'本次测试不可用' };
async function ticket() { return (await rpc(fixture.ipc_socket, { command: 'ticket' })).ticket; }
async function openServer(page, profile) {
  const selected=typeof profile==='string'?Object.values(fixture.profiles).find(item=>item.name===profile):profile;
  if(!selected?.id)throw new Error('owned synthetic profile required');
  console.log('OPEN', selected.name);
  await page.getByRole('button', { name: '服务器', exact: true }).click();
  const item = page.locator(`[data-testid="channel-summary"][data-server-id="${selected.id}"]`).locator('.server-main'); await item.waitFor({ state: 'visible', timeout: 8000 }); await item.click(); console.log('CLICKED', selected.name);
  const section = page.getByTestId('codex-model-test'); await section.waitFor({ state: 'visible' }); return section;
}
async function screenshot(page, name) { const file = path.join(out, name + '.png'); await page.evaluate(async()=>{window.scrollTo({top:0,left:0,behavior:'instant'});await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));});await expect.poll(()=>page.evaluate(()=>window.scrollY)).toBe(0);const box=await page.getByTestId('codex-model-test').boundingBox();const cdp=await page.context().newCDPSession(page);const capture=await cdp.send('Page.captureScreenshot',{format:'png',captureBeyondViewport:true,clip:{...box,scale:1}});await cdp.detach();fs.writeFileSync(file,Buffer.from(capture.data,'base64'),{mode:0o600}); evidence.screenshots.push(name + '.png'); }
async function layout(page) {await page.mouse.move(0,0);await expect.poll(()=>page.evaluate(()=>document.documentElement.scrollWidth-innerWidth),{timeout:5000}).toBeLessThanOrEqual(2);await page.evaluate(async()=>{await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));}); const summary=await page.getByTestId('codex-model-test').evaluate(section=>{const shown=el=>{const b=el.getBoundingClientRect(),s=getComputedStyle(el);return b.width>0&&b.height>0&&s.display!=='none'&&s.visibility!=='hidden';};const els=[...section.querySelectorAll('h2,p,label,button,strong,input,select,.metric-line')].filter(shown);return{viewport:innerWidth,document_width:document.documentElement.scrollWidth,body_font_px:parseFloat(getComputedStyle(document.body).fontSize),overflow:els.filter(el=>{const b=el.getBoundingClientRect();return b.left < -2 || b.right > innerWidth+2 || !el.matches('input,select')&&el.scrollWidth>el.clientWidth+3;}).map(el=>({tag:el.tagName,class:el.className})),global_overflow:[...document.querySelectorAll('*')].filter(shown).filter(el=>el.getBoundingClientRect().right>innerWidth+2).map(el=>({tag:el.tagName,class:String(el.className)})).slice(0,12)};});evidence.last_geometry=summary;expect(summary.document_width).toBeLessThanOrEqual(summary.viewport+2);expect(summary.overflow).toEqual([]);const low=(await contrast(page)).filter(x=>x.ratio<x.required);expect(low).toEqual([]);return summary; }

const browser = await chromium.launch({ channel: 'chrome', headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, colorScheme: 'light', reducedMotion: 'reduce', recordVideo:{dir:path.join(out,'video'),size:{width:1440,height:900}} });
const page = await context.newPage();
page.on('request',request=>{if(request.url().endsWith('/model-test'))evidence.model_api_calls++;if(request.url().endsWith('/model-test/preview'))evidence.preview_api_calls++;});
await page.addInitScript(() => { localStorage.setItem('tm-theme', 'system'); const install = () => { if (!document.documentElement) return false; const style = document.createElement('style'); style.textContent = '[data-sensitive]{color:transparent!important;background:#85858a!important;text-shadow:none!important}[data-sensitive] *{visibility:hidden!important}'; style.id='model-audit-privacy'; document.documentElement.append(style); return true; }; if (!install()) document.addEventListener('DOMContentLoaded', install, {once:true}); });
try {
  const origin = fixture.origin; await page.goto(origin + '/#ticket=' + encodeURIComponent(await ticket()));
  await page.getByRole('heading', { name: '隧道总览', exact: true }).waitFor();
  for(const asset of await page.evaluate(()=>[...document.querySelectorAll('script[src],link[rel="stylesheet"]')].map(el=>el.getAttribute('src')||el.getAttribute('href')).filter(x=>x?.startsWith('/assets/')))){const response=await page.request.get(origin+asset);evidence.assets.push({path:asset,sha256:crypto.createHash('sha256').update(await response.body()).digest('hex')});}
  const initial = await openServer(page, fixture.profiles.healthy.name);
  const preview = initial.getByRole('button', { name: '读取远程模型配置', exact: true });
  const consent = initial.getByRole('checkbox', { name: /允许使用远端 API 密钥/ });
  const run = initial.getByRole('button', { name: '测试鉴权与模型调用', exact: true });
  await expect(preview).toBeEnabled(); await expect(consent).not.toBeChecked(); await expect(run).toBeDisabled();
  await screenshot(page, 'light-1440-initial'); evidence.checks.push({ name:'initial state requires explicit target and consent', result:'PASS', model_requests:0 });
  for (const item of cases) {
    console.log('CASE', item);
    const control = await rpc(fixture.fixture_socket, { command:'case', case:item });
    const section = await openServer(page, control.profile);
    const read = section.getByRole('button', { name: '读取远程模型配置', exact: true });
    await expect(read).toBeEnabled();const before=await rpc(fixture.fixture_socket,{command:'status'});
    const previewResponse=page.waitForResponse(response=>response.url().endsWith(`/servers/${control.profile.id}/model-test/preview`)&&response.request().method()==='POST');
    await read.click();
    const previewResult=await (await previewResponse).json(); if(previewResult.config_state!=='READY')throw new Error('fixture preview '+previewResult.config_state);
    await section.getByTestId('codex-model-preview').waitFor({ state:'visible' });
    const url = section.getByLabel('服务地址（HTTPS）', { exact:true });
    const model = section.getByLabel('模型名称', { exact:true });
    const protocol = section.getByLabel('接口协议', { exact:true });
    if (!(await url.inputValue()).startsWith('https://api.synthetic.example.com/v1') || !(await model.inputValue()).includes('synthetic-tiny-model') || !(await protocol.inputValue())) throw new Error(item + ' preview mismatch');
    const afterPreview=await rpc(fixture.fixture_socket,{command:'status'});expect(afterPreview.requests).toBe(before.requests);expect(afterPreview.helper_calls).toBe(before.helper_calls+1);
    const check = section.getByRole('checkbox', { name:/允许使用远端 API 密钥/ });await expect(check).not.toBeChecked();
    const button = section.getByRole('button', { name:'测试鉴权与模型调用', exact:true });await expect(button).toBeDisabled();
    if(item==='chat')await protocol.selectOption('chat');
    await check.check();
    if(item==='responses'){await model.fill('synthetic-other');await expect(check).not.toBeChecked();await expect(button).toBeDisabled();await model.fill('synthetic-tiny-model');await check.check();await screenshot(page,'light-1440-consent');}
    const resultResponse=page.waitForResponse(response=>response.url().endsWith(`/servers/${control.profile.id}/model-test`)&&response.request().method()==='POST');
    await button.click();const resultHttp=await resultResponse;expect(resultHttp.status()).toBe(200);const result=await resultHttp.json();await expect(check).not.toBeChecked();await expect(button).toBeDisabled();
    await section.getByTestId('codex-model-result').waitFor({ state:'visible' });
    await expect(section.getByTestId('codex-model-result')).toContainText(labels[item]);const text = await section.getByTestId('codex-model-result').innerText();
    if (!text.includes(labels[item])) throw new Error(item + ' result mismatch: ' + text.slice(0,120));
    const success = item === 'responses' || item === 'chat';
    if (success && !text.includes('已成功生成')) throw new Error(item + ' missing verified generation');
    if (!success && text.includes('已成功生成')) throw new Error(item + ' false success');
    await screenshot(page, `light-1440-${item}`);
    expect(result.llm_completion_verified).toBe(success);expect(text.includes('已验证')).toBe(success);
    const after=await rpc(fixture.fixture_socket,{command:'status'});expect(after.requests-before.requests).toBe(['credential','tls','dns'].includes(item)?0:1);expect(after.helper_calls-afterPreview.helper_calls).toBe(1);
    evidence.checks.push({ name:'actual synthetic case '+item, result:'PASS', expected:labels[item], backend_state:result.state, authentication:result.authentication, model_completion:result.model_completion, http_status:result.http_status, verified_generation:success, provider_text_returned:false,actual_requests:after.requests-before.requests,actual_helpers:after.helper_calls-before.helper_calls,preview_sent_zero_model_requests:true,consent_reset:true });
  }
  // A known successful result is used for the complete layout matrix.
  const control = await rpc(fixture.fixture_socket, { command:'case', case:'responses' }); const known = await openServer(page, control.profile);
  await known.getByRole('button',{name:'读取远程模型配置',exact:true}).click();await expect(known.getByTestId('codex-model-preview')).toBeVisible();
  const url=known.getByLabel('服务地址（HTTPS）',{exact:true}),model=known.getByLabel('模型名称',{exact:true}),protocol=known.getByLabel('接口协议',{exact:true}),check=known.getByRole('checkbox',{name:/允许使用远端 API 密钥/}),button=known.getByRole('button',{name:'测试鉴权与模型调用',exact:true});
  // Actual keyboard traversal including native select, checkbox and Enter.
  await url.focus();await page.keyboard.press('Tab');await expect(model).toBeFocused();await page.keyboard.press('Tab');await expect(protocol).toBeFocused();await page.keyboard.press('Tab');await expect(check).toBeFocused();await page.keyboard.press('Space');await expect(check).toBeChecked();await page.keyboard.press('Tab');await expect(button).toBeFocused();const focus=await button.evaluate(el=>({outline:getComputedStyle(el).outlineStyle,width:parseFloat(getComputedStyle(el).outlineWidth)}));expect(focus.outline).not.toBe('none');expect(focus.width).toBeGreaterThanOrEqual(2);await screenshot(page,'light-1440-keyboard-focus');await page.keyboard.press('Enter');await expect(known.getByTestId('codex-model-result')).toContainText('已验证模型可调用');
  evidence.checks.push({name:'actual keyboard fields/select/checkbox/Enter',result:'PASS',focus});
  const credentialSection=page.getByRole('region',{name:'远程 Codex 登录凭据',exact:true});const credentialConsent=credentialSection.getByRole('checkbox',{name:'允许在远端读取 Codex auth.json 并仅返回状态',exact:true});await credentialConsent.check();const credentialResponse=page.waitForResponse(response=>response.url().endsWith(`/servers/${control.profile.id}/credentials/codex/check`)&&response.request().method()==='POST');await credentialSection.getByRole('button',{name:'检查远程 Codex 登录凭据',exact:true}).click();const credential=await(await credentialResponse).json();expect(credential.credential_state).toBe('READABLE');await expect(known.getByTestId('codex-model-result')).toContainText('已成功生成');await expect(credentialSection).toContainText('读取凭据不代表模型可调用');await expect(check).not.toBeChecked();evidence.checks.push({name:'separate credential read preserves actual model success without contradictory untested fields',result:'PASS',credential_state:'READABLE',model_success_preserved:true,consent_not_shared:true});
  for(const theme of ['light','dark']) {await page.setViewportSize(viewports[0]);await page.locator('.sidebar').getByRole('button',{name:theme==='light'?'切换主题：浅色':'切换主题：深色',exact:true}).click();await expect(page.locator('html')).toHaveAttribute('data-theme',theme);
    for(const viewport of viewports) {await page.setViewportSize(viewport);const geometry=await layout(page);await screenshot(page,`${theme}-${viewport.width}x${viewport.height}-success`);evidence.checks.push({name:`${theme}-${viewport.width} layout/contrast`,result:'PASS',geometry});}
    for(const viewport of [viewports[0],viewports[3]]) {await page.setViewportSize(viewport);await page.evaluate(()=>document.documentElement.style.fontSize='32px');const geometry=await layout(page);expect(geometry.body_font_px).toBe(32);await screenshot(page,`${theme}-${viewport.width}x${viewport.height}-font200-success`);evidence.checks.push({name:`${theme}-${viewport.width} font200`,result:'PASS',geometry});await page.evaluate(()=>document.documentElement.style.fontSize='');}
  }
  await page.setViewportSize(viewports[0]);await page.locator('.sidebar').getByRole('button',{name:'切换主题：跟随系统',exact:true}).click();await page.emulateMedia({colorScheme:'light',reducedMotion:'reduce'});await expect(page.locator('html')).toHaveAttribute('data-theme','light');await page.emulateMedia({colorScheme:'dark',reducedMotion:'reduce'});await expect(page.locator('html')).toHaveAttribute('data-theme','dark');expect(await page.evaluate(()=>matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);await screenshot(page,'system-dark-1440-success');evidence.checks.push({name:'System follows light/dark and reduced-motion',result:'PASS'});
  await check.check();await model.fill('synthetic-changed-model');await expect(check).not.toBeChecked();await expect(button).toBeDisabled();await expect(known.getByTestId('codex-model-historical')).toBeVisible();await screenshot(page,'system-dark-1440-historical');evidence.checks.push({name:'changing target resets consent and labels previous result',result:'PASS'});
  for(const key of ['stopped','external']) {const before=await rpc(fixture.fixture_socket,{command:'status'}),calls=evidence.model_api_calls;const section=await openServer(page,fixture.profiles[key].name);await expect(section.getByRole('button',{name:'读取远程模型配置',exact:true})).toBeDisabled();await expect(section.getByRole('checkbox',{name:/允许使用远端 API 密钥/})).toBeDisabled();await expect(section.getByRole('button',{name:'测试鉴权与模型调用',exact:true})).toBeDisabled();const after=await rpc(fixture.fixture_socket,{command:'status'});expect(after.requests).toBe(before.requests);expect(after.helper_calls).toBe(before.helper_calls);expect(evidence.model_api_calls).toBe(calls);await screenshot(page,`system-dark-1440-${key}`);evidence.checks.push({name:key+' disabled zero remote model action',result:'PASS',automatic_connection:false});}
  const repeatControl=await rpc(fixture.fixture_socket,{command:'case',case:'responses'}),repeat=await openServer(page,repeatControl.profile);await repeat.getByRole('button',{name:'读取远程模型配置',exact:true}).click();await expect(repeat.getByTestId('codex-model-preview')).toBeVisible();const repeatConsent=repeat.getByRole('checkbox',{name:/允许使用远端 API 密钥/}),repeatButton=repeat.getByRole('button',{name:'测试鉴权与模型调用',exact:true});await repeatConsent.check();const firstRepeatResponse=page.waitForResponse(response=>response.url().endsWith(`/servers/${repeatControl.profile.id}/model-test`)&&response.request().method()==='POST');await repeatButton.click();expect((await (await firstRepeatResponse).json()).state).toBe('SUCCESS');await expect(repeat.getByTestId('codex-model-result')).toContainText('已验证模型可调用');await expect(repeat.getByTestId('codex-model-historical')).toHaveCount(0);const beforeRepeat=await rpc(fixture.fixture_socket,{command:'status'});await repeatConsent.check();const repeatResponse=page.waitForResponse(response=>response.url().endsWith(`/servers/${repeatControl.profile.id}/model-test`)&&response.request().method()==='POST');await repeatButton.click();const cooldown=await repeatResponse;expect(cooldown.status()).toBe(429);expect((await cooldown.json()).code).toBe('MODEL_TEST_COOLDOWN');await expect(repeat.getByTestId('codex-model-error')).toContainText('等待 30 秒');await expect(repeat.getByTestId('codex-model-historical')).toBeVisible();await expect(repeat.getByTestId('codex-model-result')).toContainText('此前结果');const afterRepeat=await rpc(fixture.fixture_socket,{command:'status'});expect(afterRepeat.requests).toBe(beforeRepeat.requests);expect(afterRepeat.helper_calls).toBe(beforeRepeat.helper_calls);await screenshot(page,'system-dark-1440-cooldown-historical');evidence.checks.push({name:'repeat identical target cooldown labels old success historical and sends zero provider requests',result:'PASS',http_status:429,code:'MODEL_TEST_COOLDOWN',old_success_historical:true,actual_new_requests:0,actual_new_helpers:0});
} catch (error) { evidence.debug=await page.evaluate(()=>({scrollX,scrollY,innerWidth,client:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth,items:[...document.querySelectorAll('*')].filter(el=>{const r=el.getBoundingClientRect();return r.right>innerWidth+2||el.scrollWidth>el.clientWidth+3}).map(el=>({tag:el.tagName,class:String(el.className),w:el.clientWidth,sw:el.scrollWidth,right:el.getBoundingClientRect().right,left:el.getBoundingClientRect().left,visibility:getComputedStyle(el).visibility,display:getComputedStyle(el).display})).slice(0,60)}));evidence.failures.push({name:'model UI audit', result:'FAIL', detail:String(error.message || error)});try{await screenshot(page,'failure');}catch{} }
finally { evidence.status = evidence.failures.length ? 'FAIL' : 'PASS'; evidence.completed_at = new Date().toISOString(); await context.close(); const video=await page.video().path();const saved=path.join(out,'model-test-Chinese-flow.webm');fs.renameSync(video,saved);evidence.video='model-test-Chinese-flow.webm';fs.writeFileSync(path.join(out,'evidence.json'), JSON.stringify(evidence,null,2), {mode:0o600}); await browser.close(); console.log(JSON.stringify({status:evidence.status, checks:evidence.checks.length, failures:evidence.failures, screenshots:evidence.screenshots.length, evidence:path.join(out,'evidence.json')},null,2)); if(evidence.status==='FAIL')process.exitCode=1; }
