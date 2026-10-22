import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, FileSearch, LoaderCircle, Play } from 'lucide-react';
import type { CodexModelPreview, CodexModelTestResult, CodexModelTestState, CodexWireApi, Runtime, Server } from '../../../shared/types';
import * as api from './api';
import { codexCredentialLabel, fmtMs, fmtTime, isEnabled, modeLabel } from './ui';
import './codex-model-test.css';

const stateLabels: Record<CodexModelTestState, string> = {
  SUCCESS: '已验证模型可调用', AUTH_REJECTED: 'API 密钥鉴权失败', PERMISSION_DENIED: '服务拒绝访问',
  RATE_LIMITED: '额度或速率限制', MODEL_UNAVAILABLE: '模型不可用', NETWORK_ERROR: '代理链路请求失败',
  TLS_ERROR: 'TLS 证书验证失败', TIMEOUT: '模型请求超时', INVALID_RESPONSE: '服务响应格式不符',
  EMPTY_OUTPUT: '没有返回生成文本', INCOMPLETE: '模型生成未完成', CREDENTIAL_UNAVAILABLE: 'API 密钥不可用',
  CHECK_UNAVAILABLE: '本次测试不可用', UPSTREAM_ERROR: '服务商返回错误',
};
const stateDescriptions: Record<CodexModelTestState, string> = {
  SUCCESS: '已收到符合所选协议的完整生成结果。本次鉴权与模型调用均已验证。',
  AUTH_REJECTED: '服务商拒绝了本次鉴权。请检查远端 API 密钥及对应的服务商地址。',
  PERMISSION_DENIED: '服务商拒绝访问该接口或模型。请检查账户权限；此结果不能证明密钥有效。',
  RATE_LIMITED: '本次请求受到额度或速率限制。请在服务商控制台检查额度，稍后手动重试。',
  MODEL_UNAVAILABLE: '服务商未能提供所选模型。请核对模型名称、接口协议和账户权限。',
  NETWORK_ERROR: '通过当前代理通道未能完成模型请求。请先检查远程监听、本机代理出口和网络。',
  TLS_ERROR: '服务商的 TLS 证书未通过验证。请检查服务地址与证书；不会跳过证书验证。',
  TIMEOUT: '本次模型请求超过时间限制。后台不会自动重试，请检查网络及服务商状态。',
  INVALID_RESPONSE: '返回内容不符合所选模型接口协议，未能证明模型生成成功。请核对服务地址和协议。',
  EMPTY_OUTPUT: '服务已返回响应，但没有可验证的生成文本；未认定模型调用成功。',
  INCOMPLETE: '服务返回的生成过程未完成；未认定模型调用成功。',
  CREDENTIAL_UNAVAILABLE: '远端 auth.json 中的 API 密钥不可用，本次未向服务商发送模型请求。请检查上方凭据读取状态。',
  CHECK_UNAVAILABLE: '本次测试未能获得可验证结果，请检查托管连接和远端工具后手动重试。',
  UPSTREAM_ERROR: '服务商返回了错误状态，本次未证明模型可调用。请检查服务商状态或手动重试。',
};
const previewLabels: Record<CodexModelPreview['config_state'], string> = {
  READY: '已读取远程模型配置，请核对下方目标。', NOT_FOUND: '远程模型配置文件不存在，请手动填写服务地址、模型及协议。',
  UNREADABLE: '远程模型配置不可读取，请手动填写目标，或在远端检查配置权限。',
  INVALID_CONFIG: '远程模型配置格式无效或不完整，请核对下方内容并补全。',
  UNSUPPORTED_PROVIDER: '远程配置未提供受支持的 API 密钥服务，请手动填写兼容接口的目标。',
  REMOTE_TOOL_UNAVAILABLE: '远端模型配置读取工具不可用，请检查远端工具或手动填写目标。',
  CHECK_UNAVAILABLE: '远程模型配置未读取完成，不能使用未确认的目标。',
};
const actionErrors: Record<string, string> = {
  CONSENT_REQUIRED: '请先确认目标服务，再勾选一次模型测试授权。',
  INVALID_CREDENTIAL_SOURCE: '凭据来源无效，请从应用重新打开此页面。',
  EXTERNAL_RESOURCE: '此服务器仅供外部观察，不能发送模型测试请求。',
  CONNECTION_REQUIRED: '请先启用托管通道并等待 SSH 连接建立。',
  CONNECTION_CHANGED: '测试期间连接已变化，结果不可用；请等待连接稳定后手动重试。',
  OWNERSHIP_MISMATCH: '托管连接归属无法验证，已拒绝发送请求。',
  REVISION_CONFLICT: '服务器配置已变化，请重新核对目标并授权测试。',
  REVISION_REQUIRED: '缺少最新配置版本，请刷新页面后重新核对目标。',
  VALIDATION_ERROR: '目标参数未通过检查，请核对 HTTPS 服务地址、模型名称及接口协议。',
  INVALID_TARGET: '服务地址未通过检查，请使用不含密码、查询参数或片段的 HTTPS 地址。',
  INVALID_MODEL: '模型名称未通过检查，请填写服务商提供的准确模型名称。',
  UNSUPPORTED_WIRE_API: '接口协议不受支持，请选择 Responses 或 Chat Completions。',
  MODEL_TEST_BUSY: '本通道已有模型测试正在进行，请等待完成后再操作。',
  MODEL_TEST_COOLDOWN: '刚刚已发送一次模型测试，请等待 30 秒后重新授权，避免重复消耗额度。',
  SESSION_REQUIRED: '本机会话已过期，请从应用重新打开控制台。',
  CSRF_REQUIRED: '会话验证失败，请从应用重新打开控制台。',
  STORAGE_UNAVAILABLE: '本机数据暂不可写，本次测试未执行。请检查磁盘和权限。',
};

function actionError(error: unknown) {
  const code = (error as { code?: string })?.code;
  return code && Object.hasOwn(actionErrors, code) ? actionErrors[code] : '模型测试未完成，请确认连接和本机会话后重试。';
}

function targetValidation(baseUrl: string, model: string, wireApi: string) {
  if (!baseUrl.trim()) return '请填写或读取服务地址。';
  try {
    const url = new URL(baseUrl.trim());
    if (url.protocol !== 'https:' || !url.hostname || url.username || url.password || url.search || url.hash)
      return '服务地址必须使用 HTTPS，且不能包含密码、查询参数或片段。';
  } catch { return '请填写完整的 HTTPS 服务地址。'; }
  if (!model.trim()) return '请填写服务商支持的模型名称。';
  if (!wireApi) return '请选择与服务商一致的接口协议。';
  return '';
}

function ResultLine({ label, value, tone = 'muted' }: { label: string; value: string; tone?: string }) {
  return <div className="metric-line"><span>{label}</span><strong className={tone}>{value}</strong></div>;
}

type Target = { base_url: string; model: string; wire_api: CodexWireApi; revision: number; mode: Server['mode'] };
type TestObservation = { result: CodexModelTestResult; target: Target; generation: number };

export function CodexModelTest({ server, runtime, blocked, onBusyChange }: {
  server: Server; runtime?: Runtime; blocked: boolean; onBusyChange: (busy: boolean) => void;
}) {
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('');
  const [wireApi, setWireApi] = useState<CodexWireApi | ''>('');
  const [consent, setConsent] = useState(false);
  const [preview, setPreview] = useState<CodexModelPreview | null>(null);
  const [busy, setBusy] = useState<'preview' | 'test' | null>(null);
  const [error, setError] = useState('');
  const [observation, setObservation] = useState<TestObservation | null>(null);
  const generation = useRef(0);
  const pending = useRef(false);
  const owner = useRef(server.id);
  const busyChanged = useRef(onBusyChange);
  busyChanged.current = onBusyChange;
  const currentScope = `${server.id}:${server.revision}`;
  const scope = useRef(currentScope);
  scope.current = currentScope;
  const external = server.management !== 'MANAGED';
  const canUseChannel = !external && isEnabled(server) && runtime?.ssh_connected === true && !runtime.stale;

  useEffect(() => {
    generation.current += 1;
    setConsent(false);
    setPreview(null);
    setError('');
    setBusy(null);
    pending.current = false;
    busyChanged.current(false);
    if (owner.current !== server.id) {
      owner.current = server.id;
      setBaseUrl('');
      setModel('');
      setWireApi('');
      setObservation(null);
    }
    return () => { generation.current += 1; busyChanged.current(false); };
  }, [server.id, server.revision]);
  useEffect(() => { if (!canUseChannel) setConsent(false); }, [canUseChannel]);

  const invalidateTarget = () => { generation.current += 1; setConsent(false); setError(''); };
  const setWorking = (value: 'preview' | 'test' | null) => { pending.current = value !== null; setBusy(value); busyChanged.current(value !== null); };
  const validResult = (value: CodexModelTestResult) => value && value.source === 'REMOTE_CODEX_AUTH_JSON'
    && value.server_id === server.id && value.ownership === 'MANAGED'
    && typeof value.state === 'string' && Object.hasOwn(stateLabels, value.state)
    && ['VERIFIED', 'REJECTED', 'UNKNOWN', 'NOT_TESTED'].includes(value.authentication)
    && ['SUCCEEDED', 'FAILED', 'NOT_TESTED'].includes(value.model_completion)
    && typeof value.llm_completion_verified === 'boolean'
    && (value.credential_state === 'NOT_CHECKED' || Object.hasOwn(codexCredentialLabel, value.credential_state))
    && (value.http_status === null || Number.isInteger(value.http_status) && value.http_status >= 100 && value.http_status <= 599)
    && (value.total_ms === null || Number.isFinite(value.total_ms) && value.total_ms >= 0)
    && typeof value.observed_at === 'string';

  const readPreview = async () => {
    if (!canUseChannel || blocked || pending.current) return;
    const requestGeneration = ++generation.current;
    const requestScope = currentScope;
    setConsent(false);
    setError('');
    setWorking('preview');
    try {
      const value = await api.previewCodexModel(server.id);
      if (requestGeneration !== generation.current || scope.current !== requestScope) return;
      if (!value || value.server_id !== server.id || value.ownership !== 'MANAGED'
          || value.profile_revision !== server.revision || !Object.hasOwn(previewLabels, value.config_state)
          || value.base_url !== null && typeof value.base_url !== 'string'
          || value.model !== null && typeof value.model !== 'string'
          || ![null, 'responses', 'chat'].includes(value.wire_api) || typeof value.observed_at !== 'string') {
        setError('远程配置未返回可验证的目标，请刷新页面并手动核对配置。');
        return;
      }
      setPreview(value);
      setBaseUrl(value.base_url || '');
      setModel(value.model || '');
      setWireApi(value.wire_api === 'responses' || value.wire_api === 'chat' ? value.wire_api : '');
    } catch (caught) {
      if (requestGeneration === generation.current && scope.current === requestScope) setError(actionError(caught));
    } finally {
      if (requestGeneration === generation.current && scope.current === requestScope) setWorking(null);
    }
  };

  const validation = targetValidation(baseUrl, model, wireApi);
  const runTest = async () => {
    if (!canUseChannel || blocked || pending.current || !consent || validation || !wireApi) return;
    const requestGeneration = ++generation.current;
    const requestScope = currentScope;
    const target: Target = { base_url: baseUrl.trim(), model: model.trim(), wire_api: wireApi, revision: server.revision, mode: server.mode };
    setConsent(false);
    setError('');
    setWorking('test');
    try {
      const value = await api.testCodexModel(server.id, {
        source: 'REMOTE_CODEX_AUTH_JSON', consent: true, base_url: target.base_url,
        model: target.model, wire_api: target.wire_api, expected_revision: target.revision,
      });
      if (requestGeneration !== generation.current || scope.current !== requestScope) return;
      if (!validResult(value)) { setError('模型测试未返回可验证的结果，本次不能认定鉴权或生成成功。'); return; }
      setObservation({ result: value, target, generation: requestGeneration });
    } catch (caught) {
      if (requestGeneration === generation.current && scope.current === requestScope) setError(actionError(caught));
    } finally {
      if (requestGeneration === generation.current && scope.current === requestScope) setWorking(null);
    }
  };

  const result = observation?.result;
  const verified = result?.state === 'SUCCESS' && result.llm_completion_verified === true
    && result.authentication === 'VERIFIED' && result.model_completion === 'SUCCEEDED';
  const inconsistentSuccess = result?.state === 'SUCCESS' && !verified;
  const historical = !!observation && (observation.generation !== generation.current || !canUseChannel
    || observation.target.revision !== server.revision || observation.target.mode !== server.mode
    || observation.target.base_url !== baseUrl.trim() || observation.target.model !== model.trim() || observation.target.wire_api !== wireApi);
  const channelHint = external ? '外部服务仅供观察，不能读取模型配置或发送测试请求。'
    : runtime?.stale ? 'SSH 状态观测已过期，请恢复实时同步后再测试。'
    : '请先启用此托管通道并等待 SSH 连接建立，再读取配置或测试模型。';

  return <section className="content-section codex-model-test" aria-labelledby="codex-model-test-heading" data-testid="codex-model-test">
    <div className="section-heading">
      <div><h2 id="codex-model-test-heading">模型调用测试</h2><p>使用远端 API 密钥，验证服务商是否接受鉴权并完成一次模型生成。</p></div>
      <button type="button" className="quiet-button" disabled={!canUseChannel || blocked || !!busy} onClick={readPreview}>
        {busy === 'preview' ? <LoaderCircle size={17} className="spin"/> : <FileSearch size={17}/>}读取远程模型配置
      </button>
    </div>
    <p className="field-note">读取配置只获取服务地址、模型和接口协议，不读取 API 密钥，也不会向服务商发送请求。请核对目标后再单独授权测试。</p>
    {preview && <p className="field-note" role="status" data-testid="codex-model-preview">{previewLabels[preview.config_state]} 读取时间：{fmtTime(preview.observed_at)}。</p>}
    <div className="model-target-card">
      <div className="form-grid">
        <label className="wide">服务地址（HTTPS）
          <input type="url" autoComplete="off" spellCheck={false} value={baseUrl} disabled={external || !!busy}
            placeholder="读取配置后确认，或填写服务商的 HTTPS 地址" aria-describedby="model-target-help"
            onChange={event => { invalidateTarget(); setBaseUrl(event.target.value); }}/>
        </label>
        <label>模型名称
          <input type="text" autoComplete="off" spellCheck={false} value={model} disabled={external || !!busy}
            placeholder="填写服务商支持的模型名称" onChange={event => { invalidateTarget(); setModel(event.target.value); }}/>
        </label>
        <label>接口协议
          <select aria-label="接口协议" value={wireApi} disabled={external || !!busy} onChange={event => { invalidateTarget(); setWireApi(event.target.value as CodexWireApi | ''); }}>
            <option value="">请选择接口协议</option><option value="responses">Responses</option><option value="chat">Chat Completions</option>
          </select>
        </label>
      </div>
      <p className="field-note" id="model-target-help">服务地址决定 API 密钥发送给谁。请只使用你信任的服务商地址，且不要在地址中填写密钥。接口协议需与服务商一致。</p>
      <div className="model-request-summary"><span>测试网络出口</span><strong>{modeLabel[server.mode]}</strong><span>请求方式</span><strong>一次简短生成 · 不自动重试</strong></div>
    </div>
    <label className="check-label model-consent"><input type="checkbox" checked={consent} disabled={!canUseChannel || blocked || !!busy || !!validation}
      onChange={event => setConsent(event.target.checked)}/>允许使用远端 API 密钥向上述服务发送一次模型测试请求（可能消耗额度）</label>
    <p className="field-note">密钥仅在远端读取并发送给上述服务；不会返回到本机。测试使用当前通道的代理，不绕过代理，不使用 OAuth 令牌；页面不保存服务响应正文或生成文本。</p>
    <p className="field-note">仅发送简短测试。模型达到测试输出上限时会显示未完成；后台不会自动重试，再次测试需重新授权。</p>
    {!canUseChannel && <p className="field-note">{channelHint}</p>}
    {canUseChannel && validation && <p className="field-note" data-testid="codex-model-target-validation">{validation}</p>}
    <div className="model-test-actions">
      <button type="button" className="primary-button" disabled={!canUseChannel || blocked || !!busy || !consent || !!validation} onClick={runTest}>
        {busy === 'test' ? <LoaderCircle size={17} className="spin"/> : <Play size={17}/>}测试鉴权与模型调用
      </button>
      <span className="field-note">每次测试都需要重新勾选授权。</span>
    </div>
    {busy && <div className="loading-line" role="status"><LoaderCircle size={20} className="spin"/>{busy === 'preview' ? '正在读取远程模型配置' : '正在通过当前代理测试模型，最多发送一次请求'}</div>}
    {error && <div className="form-error" role="alert" data-testid="codex-model-error"><AlertTriangle size={17}/>{error}</div>}
    <div className="diagnostic-result model-test-result" role="status" aria-live="polite" data-testid="codex-model-result">
      {result ? <>
        <div className={`model-test-outcome ${verified ? 'good' : 'warn'}`}>{verified ? <CheckCircle2 size={20}/> : <AlertTriangle size={20}/>}
          <strong>{inconsistentSuccess ? '测试结果不可验证' : stateLabels[result.state]}</strong>
          {historical && <span className="model-history-label">此前结果</span>}
        </div>
        <p className="field-note">{inconsistentSuccess ? '返回的测试字段不一致，本次不能认定鉴权或模型生成成功。' : stateDescriptions[result.state]}</p>
        {historical && <p className="field-note warn" data-testid="codex-model-historical">目标、服务器配置或连接已变化。下方保留的是测试时间的结果，不能代表当前设置。</p>}
        <ResultLine label="鉴权测试" value={inconsistentSuccess ? '无法确定' : ({ VERIFIED: '已验证', REJECTED: '被服务商拒绝', UNKNOWN: '无法确定', NOT_TESTED: '未测试' })[result.authentication] || '无法确定'} tone={verified ? 'good' : result.authentication === 'REJECTED' ? 'bad' : 'muted'}/>
        <ResultLine label="模型调用" value={verified ? '已成功生成' : result.model_completion === 'NOT_TESTED' ? '未测试' : '未证明成功'} tone={verified ? 'good' : 'muted'}/>
        <ResultLine label="HTTP 状态" value={result.http_status == null ? '未获得' : String(result.http_status)}/>
        <ResultLine label="请求总耗时" value={fmtMs(result.total_ms)}/>
        <ResultLine label="远程凭据" value={result.credential_state === 'NOT_CHECKED' ? '本次未读取' : codexCredentialLabel[result.credential_state] || '无法确定'}/>
        <ResultLine label="测试服务" value={observation.target.base_url}/><ResultLine label="测试模型" value={observation.target.model}/>
        <ResultLine label="接口协议" value={observation.target.wire_api === 'responses' ? 'Responses' : 'Chat Completions'}/>
        <ResultLine label="测试网络出口" value={modeLabel[observation.target.mode]}/><ResultLine label="测试时间" value={fmtTime(result.observed_at)}/>
      </> : <><ResultLine label="鉴权测试" value="未测试"/><ResultLine label="模型调用" value="未测试"/><p className="field-note">只有真实收到完整生成结果，才会显示“已验证模型可调用”。HTTP 200 或密钥可读取均不足以证明成功。</p></>}
    </div>
  </section>;
}
