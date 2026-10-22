import { useState } from 'react';
import { ArrowLeft, Globe2, Minus, Plus, Router, Server as ServerIcon, Zap } from 'lucide-react';
import type { Group, Runtime, Server } from '../../../shared/types';
import { IconButton, isEnabled, modeLabel, StateBadge, stateTone } from './ui';

type Props = { servers: Server[]; runtimes: Record<string, Runtime>; groups: Group[]; onSelect: (id: string) => void };

export function Topology({ servers, runtimes, groups, onSelect }: Props) {
  const [zoom, setZoom] = useState(1);
  const [filter, setFilter] = useState('all');
  const [group, setGroup] = useState('all');
  const [collapsed, setCollapsed] = useState(false);
  const visible = servers.filter(server => filter === 'all' || server.mode === filter)
    .filter(server => group === 'all' || server.group_id === group);
  const counts = visible.reduce((totals, server) => {
    const runtime = runtimes[server.id];
    if (server.management !== 'MANAGED') totals.external++;
    else if (!isEnabled(server)) totals.stopped++;
    else if (runtime?.state === 'HEALTHY' && !runtime.stale) totals.healthy++;
    else totals.attention++;
    return totals;
  }, { healthy: 0, attention: 0, stopped: 0, external: 0 });

  return <section className="content-section topology" aria-label="实时网络拓扑" data-testid="network-topology">
    <div className="section-heading"><div><h2>实时网络拓扑</h2>
      <p>请求从右向左：远程服务器 → SSH 反向隧道 → 本机代理出口 → Mac 网络。</p></div>
      <div className="topology-tools">
        <select aria-label="拓扑出口筛选" value={filter} onChange={event => setFilter(event.target.value)}>
          <option value="all">全部出口</option><option value="MAC_DIRECT">Mac 直连</option>
          <option value="CLASH_HTTP">Clash HTTP</option><option value="DISABLED">已停用</option>
        </select>
        <select aria-label="拓扑分组筛选" value={group} onChange={event => setGroup(event.target.value)}>
          <option value="all">全部分组</option>{groups.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>
        <button className="quiet-button" onClick={() => setCollapsed(value => !value)}>{collapsed ? '展开全部路径' : '查看汇总'}</button>
        <IconButton label="缩小拓扑" disabled={zoom <= .8} onClick={() => setZoom(value => Math.max(.8, value - .1))}><Minus size={17} /></IconButton>
        <IconButton label="放大拓扑" disabled={zoom >= 1.3} onClick={() => setZoom(value => Math.min(1.3, value + .1))}><Plus size={17} /></IconButton>
        <button className="quiet-button" onClick={() => { setZoom(1); setFilter('all'); setGroup('all'); setCollapsed(false); }}>适应视图</button>
      </div>
    </div>
    <div className="topology-summary" aria-label="当前筛选通道汇总">
      <span className="good">健康 {counts.healthy}</span><span className="warn">需要关注 {counts.attention}</span>
      <span>期望关闭 {counts.stopped}</span><span>外部观察 {counts.external}</span>
      <span>共 {visible.length} 条路径{visible.length > 8 ? '，向下滚动可查看全部' : ''}</span>
    </div>
    <div className="topology-map" style={{ '--topology-zoom': zoom } as React.CSSProperties}>
      <div className="topology-local"><span className="node-icon"><Zap size={23} /></span><strong>本机 Mac</strong>
        <small>网络出口</small><span className="ownership-note">应用托管</span></div>
      <div className="topology-links">
        {!visible.length ? <div className="topology-empty"><Router size={28} /><strong>暂无连接通道</strong><span>添加服务器后生成真实网络路径</span></div>
          : collapsed ? (['MAC_DIRECT', 'CLASH_HTTP', 'DISABLED'] as const).map(mode => {
            const channels = visible.filter(server => server.mode === mode);
            if (!channels.length) return null;
            return <div className="topology-exit" key={mode}><Globe2 size={20} /><strong>{modeLabel[mode]} · {channels.length} 条通道</strong>
              <div className="topology-summary">{channels.map(server => <button className="text-button" key={server.id} onClick={() => onSelect(server.id)}>
                {server.name} · {isEnabled(server) ? '期望开启' : '期望关闭'} · <StateBadge runtime={runtimes[server.id]} external={server.management !== 'MANAGED'} />
              </button>)}</div></div>;
          }) : visible.map(server => {
            const runtime = runtimes[server.id];
            const tone = runtime && !runtime.stale ? stateTone[runtime.state] : 'muted';
            return <div className={`topology-path ${tone}`} key={server.id}>
              <div className="topology-exit"><Globe2 size={20} /><strong>{modeLabel[server.mode]}</strong>
                <small>{server.mode === 'DISABLED' ? '代理已停用' : `127.0.0.1:${server.proxy_port}`}</small></div>
              <ArrowLeft size={20} className="path-arrow" />
              <div className="topology-tunnel"><Router size={19} /><strong>SSH 反向隧道</strong>
                <small>{server.management !== 'MANAGED' ? '外部连接未验证' : runtime?.ssh_connected ? '连接已建立' : '尚未建立'}</small></div>
              <ArrowLeft size={20} className="path-arrow" />
              <button className={`topology-server ${tone}`} data-testid="topology-server" data-server-id={server.id} onClick={() => onSelect(server.id)}
                title={`${server.name} · ${modeLabel[server.mode]} · ${isEnabled(server) ? '期望开启' : '期望关闭'}`}
                aria-label={`打开${server.name}的详情`}>
                <span className="node-icon"><ServerIcon size={18} /></span><span><strong>{server.name}</strong>
                  <small>{server.management === 'MANAGED' ? '应用托管' : '外部服务 · 仅观察'}</small>
                  <span>{isEnabled(server) ? '期望开启' : '期望关闭'} · <StateBadge runtime={runtime} external={server.management !== 'MANAGED'} /></span>
                </span>
              </button>
            </div>;
          })}
      </div>
    </div>
    <div className="topology-legend"><span><i className="good" />健康</span><span><i className="warn" />降级或重连</span>
      <span><i className="bad" />失败或冲突</span><span><i className="muted" />停止或未观测</span>
      <small>动画表示状态变化后的探测活动，不是实时流量。</small></div>
  </section>;
}
