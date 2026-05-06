import { useState, useEffect, useRef } from "react";

// ─── Constants ────────────────────────────────────────────────────────────────

const SYSCALLS = ["epoll_wait","read","write","futex","recvmsg","sendmsg","openat","close","mmap","munmap","brk","nanosleep","stat","fstat","poll","select","clock_gettime","getpid"];

const INITIAL_FDS = [
  { fd:0,  type:"pipe",   desc:"stdin",                    flags:"O_RDONLY", bytes:0,        age:3820, active:false },
  { fd:1,  type:"pipe",   desc:"stdout",                   flags:"O_WRONLY", bytes:142300,   age:3820, active:true  },
  { fd:2,  type:"pipe",   desc:"stderr",                   flags:"O_WRONLY", bytes:1200,     age:3820, active:false },
  { fd:3,  type:"socket", desc:"TCP 10.0.0.1:443",         flags:"O_RDWR",   bytes:980400,   age:3790, active:true  },
  { fd:4,  type:"socket", desc:"TCP 10.0.1.5:5432",        flags:"O_RDWR",   bytes:2340100,  age:3750, active:true  },
  { fd:5,  type:"socket", desc:"UNIX /var/run/docker.sock",flags:"O_RDWR",   bytes:44200,    age:3700, active:false },
  { fd:6,  type:"file",   desc:"/data/db/index.db",        flags:"O_RDWR",   bytes:8812400,  age:3650, active:true  },
  { fd:7,  type:"file",   desc:"/var/log/app/api.log",     flags:"O_WRONLY", bytes:3210000,  age:3600, active:true  },
  { fd:8,  type:"file",   desc:"/etc/config/settings.json",flags:"O_RDONLY", bytes:4096,     age:3400, active:false },
  { fd:9,  type:"epoll",  desc:"epoll fd (5 watches)",     flags:"O_RDWR",   bytes:0,        age:3820, active:true  },
  { fd:10, type:"timer",  desc:"timerfd interval=100ms",   flags:"O_RDONLY", bytes:0,        age:3500, active:true  },
  { fd:11, type:"file",   desc:"/tmp/cache/sessions.bin",  flags:"O_RDWR",   bytes:610000,   age:1200, active:false },
  { fd:12, type:"socket", desc:"TCP 10.0.2.1:6379",        flags:"O_RDWR",   bytes:220000,   age:800,  active:true  },
  { fd:13, type:"pipe",   desc:"[pipe:anon] worker→main",  flags:"O_RDWR",   bytes:88200,    age:600,  active:false },
  { fd:14, type:"file",   desc:"/proc/self/status",        flags:"O_RDONLY", bytes:512,      age:12,   active:false },
];

const COLORS = {
  bg:"#0e1014", bgPanel:"#13161c", border:"#2a2d35", dim:"#3a3d45",
  muted:"#5a5f72", text:"#c8ccd8", bright:"#e8ecf5", green:"#4ade80",
  cyan:"#22d3ee", amber:"#fbbf24", red:"#f87171", blue:"#60a5fa",
  purple:"#a78bfa", pink:"#f472b6", orange:"#fb923c", teal:"#2dd4bf",
};

// ─── Simulation ───────────────────────────────────────────────────────────────

function useSimulatedData() {
  const [tick,             setTick]             = useState(0);
  const [cpuHistory,       setCpuHistory]       = useState(()=>Array(60).fill(0).map(()=>Math.random()*30+5));
  const [syscallCounts,    setSyscallCounts]    = useState(()=>Object.fromEntries(SYSCALLS.map(s=>[s,Math.floor(Math.random()*200)])));
  const [netEvents,        setNetEvents]        = useState([
    { id:1, type:"TCP",  remote:"10.0.1.5:5432",         state:"WAIT",        latency:42, dir:"→" },
    { id:2, type:"TCP",  remote:"10.0.0.1:443",          state:"ESTABLISHED", latency:8,  dir:"↔" },
    { id:3, type:"UNIX", remote:"/var/run/docker.sock",  state:"ESTABLISHED", latency:1,  dir:"→" },
  ]);
  const [memStats,         setMemStats]         = useState({ rss:148, heap:92, pageFaults:14, allocs:320 });
  const [threads,          setThreads]          = useState([
    { id:1, name:"main",      state:"running",  cpu:34, waiting:null        },
    { id:2, name:"worker-1",  state:"blocked",  cpu:0,  waiting:"mutex-A"   },
    { id:3, name:"worker-2",  state:"running",  cpu:18, waiting:null        },
    { id:4, name:"gc",        state:"sleeping", cpu:0,  waiting:"nanosleep" },
    { id:5, name:"http-pool", state:"blocked",  cpu:0,  waiting:"epoll_wait"},
  ]);
  const [ioReadHistory,    setIoReadHistory]    = useState(()=>Array(60).fill(0).map(()=>Math.random()*800));
  const [ioWriteHistory,   setIoWriteHistory]   = useState(()=>Array(60).fill(0).map(()=>Math.random()*400));
  const [ioFiles,          setIoFiles]          = useState(()=>[
    { path:"/data/db/index.db",          type:"db",   reads:240, writes:120, bytes:88120, latency:1.2, fsyncs:18 },
    { path:"/var/log/app/api.log",       type:"log",  reads:0,   writes:380, bytes:32100, latency:0.3, fsyncs:0  },
    { path:"/etc/config/settings.json",  type:"cfg",  reads:44,  writes:0,   bytes:4096,  latency:0.2, fsyncs:0  },
    { path:"/tmp/cache/sessions.bin",    type:"tmp",  reads:88,  writes:64,  bytes:61000, latency:0.8, fsyncs:2  },
    { path:"/data/db/wal.db-shm",        type:"db",   reads:120, writes:200, bytes:20480, latency:4.1, fsyncs:34 },
    { path:"/proc/self/status",          type:"proc", reads:480, writes:0,   bytes:512,   latency:0.05,fsyncs:0  },
  ]);
  const [ioTotals,         setIoTotals]         = useState({ readBytes:0, writeBytes:0, readOps:0, writeOps:0, fsyncs:0, opens:0, iowait:4.2 });
  const [ioLatencyBuckets, setIoLatencyBuckets] = useState([
    { label:"<0.1ms",  read:42, write:28 }, { label:"0.1-1ms", read:31, write:19 },
    { label:"1-5ms",   read:14, write:22 }, { label:"5-20ms",  read:8,  write:11 },
    { label:">20ms",   read:3,  write:6  },
  ]);
  const [fds,              setFds]              = useState(INITIAL_FDS);
  const [fdCountHistory,   setFdCountHistory]   = useState(()=>Array(60).fill(INITIAL_FDS.length).map((v,i)=>v+Math.floor(Math.random()*3-1)));
  const [fdEvents,         setFdEvents]         = useState([]);
  const [timeline,         setTimeline]         = useState([]);
  const [activeTab,        setActiveTab]        = useState("overview");

  useEffect(()=>{
    const iv = setInterval(()=>{
      setTick(t=>t+1);
      setCpuHistory(h=>{ const v=Math.max(0,Math.min(100,h[h.length-1]+(Math.random()-0.45)*15)); return [...h.slice(1),v]; });
      setSyscallCounts(p=>{ const u={...p}; const k=SYSCALLS[Math.floor(Math.random()*SYSCALLS.length)]; u[k]=(u[k]||0)+Math.floor(Math.random()*20); return u; });
      setMemStats(p=>({ rss:p.rss+(Math.random()>0.7?1:0), heap:Math.max(60,p.heap+(Math.random()-0.5)*3), pageFaults:p.pageFaults+(Math.random()>0.8?1:0), allocs:p.allocs+Math.floor(Math.random()*8) }));
      setNetEvents(p=>p.map(e=>({ ...e, latency:Math.max(1,e.latency+(Math.random()-0.5)*5), state:e.id===1&&Math.random()>0.7?(e.state==="WAIT"?"RECV":"WAIT"):e.state })));
      setThreads(p=>p.map(t=>({ ...t, cpu:t.state==="running"?Math.max(0,Math.min(99,t.cpu+(Math.random()-0.5)*8)):0, state:Math.random()>0.92?["running","blocked","sleeping"][Math.floor(Math.random()*3)]:t.state })));

      const nr=Math.max(0,Math.random()*1200+(Math.random()>0.85?2000:0));
      const nw=Math.max(0,Math.random()*600+(Math.random()>0.9?1500:0));
      setIoReadHistory(h=>[...h.slice(1),nr]);
      setIoWriteHistory(h=>[...h.slice(1),nw]);
      setIoFiles(p=>p.map(f=>({ ...f, reads:f.reads+(Math.random()>0.4?Math.floor(Math.random()*8):0), writes:f.writes+(Math.random()>0.6?Math.floor(Math.random()*4):0), bytes:f.bytes+Math.floor(Math.random()*512), latency:Math.max(0.05,f.latency+(Math.random()-0.5)*0.4), fsyncs:f.fsyncs+(f.type==="db"&&Math.random()>0.7?1:0) })));
      setIoTotals(p=>({ readBytes:p.readBytes+Math.floor(nr), writeBytes:p.writeBytes+Math.floor(nw), readOps:p.readOps+Math.floor(Math.random()*12), writeOps:p.writeOps+Math.floor(Math.random()*6), fsyncs:p.fsyncs+(Math.random()>0.8?1:0), opens:p.opens+(Math.random()>0.7?1:0), iowait:Math.max(0,Math.min(40,p.iowait+(Math.random()-0.5)*2)) }));
      setIoLatencyBuckets(p=>p.map((b,i)=>({ ...b, read:Math.max(1,b.read+(Math.random()-0.4)*(i===0?4:2)), write:Math.max(1,b.write+(Math.random()-0.4)*(i===0?3:2)) })));

      // FD simulation
      setFds(prev=>{
        let updated = prev.map(f=>({
          ...f,
          age: f.age+1,
          bytes: f.bytes + (f.active ? Math.floor(Math.random()*4096) : 0),
          active: Math.random()>0.75 ? !f.active : f.active,
        }));
        // occasionally open/close an fd
        if (Math.random()>0.85 && updated.length < 22) {
          const types=["file","socket","pipe"];
          const descs=["/tmp/tmp_"+Math.floor(Math.random()*9999),"TCP 10.0.3."+Math.floor(Math.random()*255)+":8080","[pipe:anon]"];
          const t=Math.floor(Math.random()*3);
          updated = [...updated, { fd:Math.max(...updated.map(f=>f.fd))+1, type:types[t], desc:descs[t], flags:"O_RDWR", bytes:0, age:0, active:true }];
        }
        if (Math.random()>0.88 && updated.length > 8) {
          const candidates = updated.filter(f=>f.fd>10);
          if (candidates.length>0) {
            const victim = candidates[Math.floor(Math.random()*candidates.length)];
            updated = updated.filter(f=>f.fd!==victim.fd);
          }
        }
        return updated;
      });
      setFdCountHistory(h=>{ const cur=INITIAL_FDS.length+Math.floor(Math.random()*6-1); return [...h.slice(1), Math.max(3,cur)]; });

      // FD events
      const fdEvtTemplates = [
        (fd)=>`openat fd=${fd} /tmp/tmp_${Math.floor(Math.random()*9999)}`,
        ()=>`close fd=${Math.floor(Math.random()*15)+3}`,
        ()=>`dup2 fd=${Math.floor(Math.random()*8)+3} → fd=${Math.floor(Math.random()*8)+12}`,
        ()=>`read fd=${Math.floor(Math.random()*8)+3} ${Math.floor(Math.random()*4096)}B`,
        ()=>`write fd=${Math.floor(Math.random()*8)+3} ${Math.floor(Math.random()*1024)}B`,
        ()=>`fcntl fd=${Math.floor(Math.random()*8)+3} F_SETFL O_NONBLOCK`,
      ];
      if (Math.random()>0.4) {
        const tmpl = fdEvtTemplates[Math.floor(Math.random()*fdEvtTemplates.length)];
        const msg = tmpl(Math.floor(Math.random()*10)+3);
        setFdEvents(p=>[{ id:Date.now(), ts:new Date().toISOString().slice(11,23), msg },...p].slice(0,60));
      }

      // Global timeline
      const allCats=["syscall","net","mem","cpu","lock","io","fd"];
      const msgs={
        syscall:["openat /etc/config.json","read fd=7 (socket)","write fd=1 (stdout)","futex WAIT mutex-A"],
        net:["TCP SYN → 10.0.1.5:5432","recv 4096B from :5432","send 128B to :443"],
        mem:["mmap 4096B ANON","page fault addr=0x7fff...","brk +8192B"],
        cpu:["preempted after 12ms","migrated core 2→5","voluntary yield"],
        lock:["mutex-A acquired thr=1","mutex-A released","RWlock read thr=3"],
        io:["read /data/db/index.db 4096B 0.8ms","write /var/log/app/api.log 512B","fsync /data/db/wal.db-shm 18ms ⚠","stat /proc/self/status ×12 (polling?)"],
        fd:["openat → fd=15 /tmp/tmpXXXX","close fd=11","dup2 fd=4→fd=16","fcntl fd=6 O_NONBLOCK","read fd=4 2048B (db)","write fd=7 512B (log)"],
      };
      const cat=allCats[Math.floor(Math.random()*allCats.length)];
      const msg=msgs[cat][Math.floor(Math.random()*msgs[cat].length)];
      setTimeline(p=>[{ id:Date.now()+1, ts:new Date().toISOString().slice(11,23), cat, msg },...p].slice(0,120));
    },600);
    return ()=>clearInterval(iv);
  },[]);

  return { tick, cpuHistory, syscallCounts, netEvents, memStats, threads, ioReadHistory, ioWriteHistory, ioFiles, ioTotals, ioLatencyBuckets, fds, fdCountHistory, fdEvents, timeline, activeTab, setActiveTab };
}

// ─── Shared primitives ────────────────────────────────────────────────────────

function Box({ title, children, flex, style={} }) {
  return (
    <div style={{ border:`1px solid ${COLORS.border}`, backgroundColor:COLORS.bgPanel, fontFamily:"'JetBrains Mono','Fira Code',monospace", display:"flex", flexDirection:"column", flex:flex||"none", overflow:"hidden", ...style }}>
      {title&&<div style={{ borderBottom:`1px solid ${COLORS.border}`, padding:"2px 8px", fontSize:10, color:COLORS.cyan, letterSpacing:"0.08em", textTransform:"uppercase", backgroundColor:"#0d1017", flexShrink:0 }}>{title}</div>}
      <div style={{ overflow:"hidden", flex:1, display:"flex", flexDirection:"column" }}>{children}</div>
    </div>
  );
}

function Badge({ label, color }) {
  return <span style={{ fontSize:9, padding:"1px 5px", borderRadius:2, border:`1px solid ${color}44`, color, backgroundColor:`${color}18`, letterSpacing:"0.06em" }}>{label}</span>;
}

function fmt(b) {
  if (b>1048576) return `${(b/1048576).toFixed(1)}MB`;
  if (b>1024)    return `${(b/1024).toFixed(1)}KB`;
  return `${Math.floor(b)}B`;
}

function fmtAge(s) {
  if (s>3600) return `${Math.floor(s/3600)}h`;
  if (s>60)   return `${Math.floor(s/60)}m`;
  return `${s}s`;
}

// ─── Sparklines ───────────────────────────────────────────────────────────────

function Sparkline({ history, color, height=44, width=280, label, value }) {
  const max=Math.max(...history,1);
  const pts=history.map((v,i)=>`${(i/(history.length-1))*width},${height-(v/max)*height}`).join(" ");
  return (
    <div style={{ padding:"6px 10px", display:"flex", gap:12, alignItems:"center" }}>
      <svg width={width} height={height} style={{ flex:1 }}>
        <defs><linearGradient id={`sg${color}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={color} stopOpacity="0.3"/><stop offset="100%" stopColor={color} stopOpacity="0.02"/></linearGradient></defs>
        <polygon points={`0,${height} ${pts} ${width},${height}`} fill={`url(#sg${color})`}/>
        <polyline points={pts} fill="none" stroke={color} strokeWidth="1.5"/>
      </svg>
      {label&&<div style={{ textAlign:"right", flexShrink:0, width:52 }}>
        <div style={{ fontSize:20, fontWeight:700, color, lineHeight:1 }}>{value}</div>
        <div style={{ fontSize:9, color:COLORS.muted, marginTop:2 }}>{label}</div>
      </div>}
    </div>
  );
}

function DualSparkline({ readH, writeH }) {
  const W=280, H=44, max=Math.max(...readH,...writeH,10);
  const pts=arr=>arr.map((v,i)=>`${(i/(arr.length-1))*W},${H-(v/max)*H}`).join(" ");
  const rP=pts(readH), wP=pts(writeH);
  const curR=readH[readH.length-1], curW=writeH[writeH.length-1];
  return (
    <div style={{ padding:"6px 10px", display:"flex", gap:10, alignItems:"center" }}>
      <svg width={W} height={H} style={{ flex:1 }}>
        <defs>
          <linearGradient id="rg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={COLORS.cyan}   stopOpacity="0.25"/><stop offset="100%" stopColor={COLORS.cyan}   stopOpacity="0.02"/></linearGradient>
          <linearGradient id="wg" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={COLORS.orange} stopOpacity="0.25"/><stop offset="100%" stopColor={COLORS.orange} stopOpacity="0.02"/></linearGradient>
        </defs>
        <polygon points={`0,${H} ${rP} ${W},${H}`} fill="url(#rg)"/>
        <polyline points={rP} fill="none" stroke={COLORS.cyan}   strokeWidth="1.5"/>
        <polygon points={`0,${H} ${wP} ${W},${H}`} fill="url(#wg)"/>
        <polyline points={wP} fill="none" stroke={COLORS.orange} strokeWidth="1.5"/>
      </svg>
      <div style={{ flexShrink:0, width:64, display:"flex", flexDirection:"column", gap:6 }}>
        <div><div style={{ fontSize:9, color:COLORS.muted }}>read/s</div><div style={{ fontSize:13, fontWeight:700, color:COLORS.cyan,   lineHeight:1 }}>{fmt(curR)}</div></div>
        <div><div style={{ fontSize:9, color:COLORS.muted }}>write/s</div><div style={{ fontSize:13, fontWeight:700, color:COLORS.orange, lineHeight:1 }}>{fmt(curW)}</div></div>
      </div>
    </div>
  );
}

// ─── Panels ───────────────────────────────────────────────────────────────────

function SyscallBars({ counts }) {
  const sorted=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,8);
  const max=sorted[0]?.[1]||1;
  const pal=[COLORS.cyan,COLORS.blue,COLORS.purple,COLORS.pink,COLORS.amber,COLORS.green,COLORS.red,COLORS.muted];
  return (
    <div style={{ padding:"4px 10px", display:"flex", flexDirection:"column", gap:3 }}>
      {sorted.map(([name,count],i)=>(
        <div key={name} style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ width:80, fontSize:9, color:COLORS.muted, textAlign:"right", flexShrink:0 }}>{name}</span>
          <div style={{ flex:1, height:8, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(count/max)*100}%`, height:"100%", backgroundColor:pal[i], transition:"width 0.4s", opacity:0.85 }}/></div>
          <span style={{ width:40, fontSize:9, color:pal[i], textAlign:"right", flexShrink:0 }}>{count}</span>
        </div>
      ))}
    </div>
  );
}

function NetPanel({ events }) {
  const sc=s=>s==="WAIT"?COLORS.amber:s==="RECV"?COLORS.cyan:s==="ESTABLISHED"?COLORS.green:COLORS.muted;
  return (
    <div style={{ padding:"4px 10px", display:"flex", flexDirection:"column", gap:4 }}>
      <div style={{ display:"flex", fontSize:9, color:COLORS.muted, marginBottom:2 }}><span style={{ width:36 }}>TYPE</span><span style={{ flex:1 }}>REMOTE</span><span style={{ width:60 }}>STATE</span><span style={{ width:52, textAlign:"right" }}>LAT</span></div>
      {events.map(e=>(
        <div key={e.id} style={{ display:"flex", fontSize:10, color:COLORS.text, alignItems:"center" }}>
          <span style={{ width:36, color:COLORS.blue }}>{e.type}</span>
          <span style={{ flex:1, color:COLORS.bright }}>{e.dir} {e.remote}</span>
          <span style={{ width:60, color:sc(e.state) }}>{e.state}</span>
          <span style={{ width:52, textAlign:"right", color:e.latency>30?COLORS.amber:COLORS.green }}>{e.latency.toFixed(0)}ms</span>
        </div>
      ))}
    </div>
  );
}

function MemPanel({ stats }) {
  return (
    <div style={{ padding:"6px 10px", display:"flex", flexDirection:"column", gap:6 }}>
      {[{ label:"RSS", value:`${stats.rss.toFixed(0)} MB`, color:COLORS.cyan },{ label:"Heap", value:`${stats.heap.toFixed(0)} MB`, color:COLORS.purple },{ label:"Page faults", value:stats.pageFaults, color:COLORS.amber },{ label:"Allocs/s", value:stats.allocs, color:COLORS.green }].map(({label,value,color})=>(
        <div key={label} style={{ display:"flex", justifyContent:"space-between", fontSize:10 }}><span style={{ color:COLORS.muted }}>{label}</span><span style={{ color }}>{value}</span></div>
      ))}
    </div>
  );
}

function IOMiniPanel({ totals, readH, writeH }) {
  return (
    <div style={{ padding:"2px 4px", display:"flex", flexDirection:"column", gap:2 }}>
      <DualSparkline readH={readH} writeH={writeH}/>
      <div style={{ display:"flex", gap:12, padding:"0 6px", flexWrap:"wrap" }}>
        {[{ label:"Read ops", value:totals.readOps, color:COLORS.cyan },{ label:"Write ops", value:totals.writeOps, color:COLORS.orange },{ label:"fsyncs", value:totals.fsyncs, color:totals.fsyncs>20?COLORS.red:COLORS.amber },{ label:"I/O wait", value:`${totals.iowait.toFixed(1)}%`, color:totals.iowait>15?COLORS.red:COLORS.green }].map(({label,value,color})=>(
          <div key={label} style={{ fontSize:9 }}><span style={{ color:COLORS.muted }}>{label} </span><span style={{ color }}>{value}</span></div>
        ))}
      </div>
    </div>
  );
}

function ThreadPanel({ threads }) {
  const sc=s=>s==="running"?COLORS.green:s==="blocked"?COLORS.red:COLORS.muted;
  return (
    <div style={{ padding:"4px 10px", display:"flex", flexDirection:"column", gap:3 }}>
      {threads.map(t=>(
        <div key={t.id} style={{ display:"flex", alignItems:"center", gap:6, fontSize:10 }}>
          <span style={{ color:sc(t.state), width:12 }}>{t.state==="running"?"▶":t.state==="blocked"?"■":"·"}</span>
          <span style={{ width:72, color:COLORS.bright }}>{t.name}</span>
          <div style={{ flex:1, height:6, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${t.cpu}%`, height:"100%", backgroundColor:t.state==="running"?COLORS.green:COLORS.dim, transition:"width 0.4s" }}/></div>
          <span style={{ width:28, textAlign:"right", color:COLORS.muted, fontSize:9 }}>{t.cpu>0?`${t.cpu.toFixed(0)}%`:""}</span>
          {t.waiting&&<span style={{ fontSize:9, color:COLORS.amber, width:90, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>⏳ {t.waiting}</span>}
        </div>
      ))}
    </div>
  );
}

function FdMiniPanel({ fds }) {
  const types = ["file","socket","pipe","epoll","timer"];
  const typeColor = { file:COLORS.cyan, socket:COLORS.blue, pipe:COLORS.purple, epoll:COLORS.amber, timer:COLORS.green };
  const counts = Object.fromEntries(types.map(t=>[t, fds.filter(f=>f.type===t).length]));
  const maxCount = Math.max(...Object.values(counts),1);
  return (
    <div style={{ padding:"4px 10px", display:"flex", flexDirection:"column", gap:4 }}>
      <div style={{ display:"flex", justifyContent:"space-between", fontSize:9, marginBottom:2 }}>
        <span style={{ color:COLORS.muted }}>open fds</span>
        <span style={{ color:COLORS.bright, fontWeight:700 }}>{fds.length}</span>
      </div>
      {types.map(t=>(
        <div key={t} style={{ display:"flex", alignItems:"center", gap:6 }}>
          <span style={{ width:44, fontSize:9, color:COLORS.muted }}>{t}</span>
          <div style={{ flex:1, height:6, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}>
            <div style={{ width:`${(counts[t]/maxCount)*100}%`, height:"100%", backgroundColor:typeColor[t], opacity:0.8, transition:"width 0.4s" }}/>
          </div>
          <span style={{ width:16, fontSize:9, color:typeColor[t], textAlign:"right" }}>{counts[t]}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Timeline ─────────────────────────────────────────────────────────────────

function Timeline({ events }) {
  const cc={ syscall:COLORS.cyan, net:COLORS.blue, mem:COLORS.purple, cpu:COLORS.green, lock:COLORS.amber, io:COLORS.orange, fd:COLORS.teal };
  const cl={ syscall:"SYS", net:"NET", mem:"MEM", cpu:"CPU", lock:"LCK", io:"I/O", fd:"FD " };
  return (
    <div style={{ padding:"4px 10px", flex:1, overflowY:"hidden", display:"flex", flexDirection:"column", gap:1 }}>
      {events.slice(0,22).map(e=>(
        <div key={e.id} style={{ display:"flex", gap:8, fontSize:9.5, alignItems:"center" }}>
          <span style={{ color:COLORS.dim, flexShrink:0, width:74 }}>{e.ts}</span>
          <span style={{ color:cc[e.cat], flexShrink:0, width:26, fontSize:8, border:`1px solid ${cc[e.cat]}44`, padding:"0 3px", borderRadius:2, textAlign:"center" }}>{cl[e.cat]}</span>
          <span style={{ color:COLORS.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{e.msg}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Tab bar ─────────────────────────────────────────────────────────────────

function TabBar({ active, onChange }) {
  const tabs=[{ id:"overview", label:"F1 Overview" },{ id:"syscalls", label:"F2 Syscalls" },{ id:"network", label:"F3 Network" },{ id:"threads", label:"F4 Threads" },{ id:"io", label:"F5 I/O" },{ id:"fd", label:"F6 FD" },{ id:"timeline", label:"F7 Timeline" }];
  return (
    <div style={{ display:"flex", gap:0, flexShrink:0, borderBottom:`1px solid ${COLORS.border}`, backgroundColor:"#0d1017", fontFamily:"'JetBrains Mono',monospace" }}>
      {tabs.map(t=>(
        <button key={t.id} onClick={()=>onChange(t.id)} style={{ padding:"4px 12px", fontSize:10, cursor:"pointer", border:"none", borderRight:`1px solid ${COLORS.border}`, backgroundColor:active===t.id?COLORS.bgPanel:"transparent", color:active===t.id?COLORS.cyan:COLORS.muted, borderBottom:active===t.id?`2px solid ${COLORS.cyan}`:"2px solid transparent", transition:"all 0.15s", letterSpacing:"0.04em" }}>{t.label}</button>
      ))}
      <div style={{ flex:1 }}/>
      <div style={{ padding:"4px 12px", fontSize:9, color:COLORS.dim, alignSelf:"center" }}>q quit · / filter · p pause</div>
    </div>
  );
}

function Header({ tick, fdCount }) {
  const up=Math.floor(tick*0.6);
  const m=Math.floor(up/60), s=up%60;
  return (
    <div style={{ display:"flex", alignItems:"center", gap:12, padding:"5px 12px", borderBottom:`1px solid ${COLORS.border}`, backgroundColor:"#0a0d11", fontFamily:"'JetBrains Mono',monospace", flexShrink:0 }}>
      <span style={{ fontSize:13, fontWeight:700, color:COLORS.cyan, letterSpacing:"0.06em" }}>⬡ bpf-inspector</span>
      <span style={{ fontSize:9, color:COLORS.border }}>│</span>
      <span style={{ fontSize:10, color:COLORS.bright }}>api-server</span>
      <Badge label="PID 18423"       color={COLORS.blue}  />
      <Badge label="Go 1.22"         color={COLORS.cyan}  />
      <Badge label="RUNNING"         color={COLORS.green} />
      <Badge label={`${fdCount} fds`} color={COLORS.teal} />
      <div style={{ flex:1 }}/>
      <span style={{ fontSize:9, color:COLORS.muted }}>uptime {String(m).padStart(2,"0")}:{String(s).padStart(2,"0")}</span>
      <span style={{ fontSize:9, color:COLORS.border }}>│</span>
      <span style={{ fontSize:9, color:COLORS.muted }}>{new Date().toLocaleTimeString("pt-BR")}</span>
    </div>
  );
}

// ─── Views ────────────────────────────────────────────────────────────────────

function OverviewView({ data }) {
  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>
      <div style={{ display:"flex", flexDirection:"column", flex:2, gap:1 }}>
        <Box title="▸ CPU" flex={1}><Sparkline history={data.cpuHistory} color={data.cpuHistory[data.cpuHistory.length-1]>80?COLORS.red:data.cpuHistory[data.cpuHistory.length-1]>50?COLORS.amber:COLORS.green} label="cpu usage" value={`${data.cpuHistory[data.cpuHistory.length-1].toFixed(0)}%`}/></Box>
        <Box title="▸ Top Syscalls" flex={1.5}><SyscallBars counts={data.syscallCounts}/></Box>
        <Box title="▸ Threads" flex={1.4}><ThreadPanel threads={data.threads}/></Box>
      </div>
      <div style={{ display:"flex", flexDirection:"column", flex:1.3, gap:1 }}>
        <Box title="▸ I/O Throughput" flex={1.1}><IOMiniPanel totals={data.ioTotals} readH={data.ioReadHistory} writeH={data.ioWriteHistory}/></Box>
        <Box title="▸ File Descriptors" flex={0.9}><FdMiniPanel fds={data.fds}/></Box>
        <Box title="▸ Network" flex={0.9}><NetPanel events={data.netEvents}/></Box>
        <Box title="▸ Memory" flex={0.65}><MemPanel stats={data.memStats}/></Box>
        <Box title="▸ Event Stream" flex={1.8}><Timeline events={data.timeline}/></Box>
      </div>
    </div>
  );
}

function SyscallView({ data }) {
  const sorted=Object.entries(data.syscallCounts).sort((a,b)=>b[1]-a[1]);
  const total=sorted.reduce((s,[,v])=>s+v,0);
  const max=sorted[0]?.[1]||1;
  const pal=[COLORS.cyan,COLORS.blue,COLORS.purple,COLORS.pink,COLORS.amber,COLORS.green,COLORS.red,COLORS.muted];
  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>
      <Box title="▸ Syscall Frequency" flex={2} style={{ overflow:"auto" }}>
        <div style={{ padding:"6px 12px" }}>
          <div style={{ display:"flex", fontSize:9, color:COLORS.muted, marginBottom:4 }}><span style={{ width:100 }}>SYSCALL</span><span style={{ flex:1 }}>FREQUENCY</span><span style={{ width:60, textAlign:"right" }}>COUNT</span><span style={{ width:50, textAlign:"right" }}>%</span></div>
          {sorted.map(([name,count],i)=>(
            <div key={name} style={{ display:"flex", alignItems:"center", gap:8, marginBottom:5, fontSize:10 }}>
              <span style={{ width:100, color:pal[i%pal.length] }}>{name}</span>
              <div style={{ flex:1, height:10, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(count/max)*100}%`, height:"100%", backgroundColor:pal[i%pal.length], opacity:0.8, transition:"width 0.4s" }}/></div>
              <span style={{ width:60, textAlign:"right", color:COLORS.text }}>{count}</span>
              <span style={{ width:50, textAlign:"right", color:COLORS.muted }}>{((count/total)*100).toFixed(1)}%</span>
            </div>
          ))}
          <div style={{ marginTop:10, paddingTop:8, borderTop:`1px solid ${COLORS.border}`, display:"flex", justifyContent:"space-between", fontSize:9 }}><span style={{ color:COLORS.muted }}>total events</span><span style={{ color:COLORS.bright }}>{total}</span></div>
        </div>
      </Box>
      <Box title="▸ Event Stream" flex={1}><Timeline events={data.timeline.filter(e=>e.cat==="syscall")}/></Box>
    </div>
  );
}

function NetworkView({ data }) {
  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>
      <div style={{ display:"flex", flexDirection:"column", flex:2, gap:1 }}>
        <Box title="▸ Active Connections" flex={1}><NetPanel events={data.netEvents}/></Box>
        <Box title="▸ Latency Trend" flex={1.5}>
          <div style={{ padding:"8px 12px", display:"flex", flexDirection:"column", gap:10 }}>
            {data.netEvents.map(e=>{ const pct=Math.min(100,(e.latency/100)*100); const color=e.latency>30?COLORS.amber:COLORS.green; return (
              <div key={e.id}><div style={{ display:"flex", justifyContent:"space-between", fontSize:9, marginBottom:3 }}><span style={{ color:COLORS.muted }}>{e.remote}</span><span style={{ color }}>{e.latency.toFixed(1)}ms</span></div><div style={{ height:6, backgroundColor:COLORS.bg, borderRadius:1 }}><div style={{ width:`${pct}%`, height:"100%", backgroundColor:color, borderRadius:1, transition:"width 0.4s" }}/></div></div>
            );})}
          </div>
        </Box>
      </div>
      <Box title="▸ Network Events" flex={1}><Timeline events={data.timeline.filter(e=>e.cat==="net")}/></Box>
    </div>
  );
}

function ThreadView({ data }) {
  const sc=s=>s==="running"?COLORS.green:s==="blocked"?COLORS.red:COLORS.muted;
  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>
      <Box title="▸ Thread State" flex={2}>
        <div style={{ padding:"8px 12px", display:"flex", flexDirection:"column", gap:8 }}>
          <div style={{ display:"flex", fontSize:9, color:COLORS.muted, gap:8 }}><span style={{ width:14 }}> </span><span style={{ width:80 }}>NAME</span><span style={{ width:70 }}>STATE</span><span style={{ flex:1 }}>CPU</span><span style={{ width:100 }}>WAITING ON</span></div>
          {data.threads.map(t=>(
            <div key={t.id} style={{ display:"flex", alignItems:"center", gap:8, fontSize:10 }}>
              <span style={{ color:sc(t.state), width:14 }}>{t.state==="running"?"▶":t.state==="blocked"?"■":"·"}</span>
              <span style={{ width:80, color:COLORS.bright }}>{t.name}</span>
              <span style={{ width:70, color:sc(t.state), fontSize:9 }}>{t.state.toUpperCase()}</span>
              <div style={{ flex:1, display:"flex", alignItems:"center", gap:6 }}>
                <div style={{ flex:1, height:8, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${t.cpu}%`, height:"100%", backgroundColor:sc(t.state), transition:"width 0.4s" }}/></div>
                <span style={{ fontSize:9, color:COLORS.muted, width:28, textAlign:"right" }}>{t.cpu>0?`${t.cpu.toFixed(0)}%`:"--"}</span>
              </div>
              <span style={{ width:100, fontSize:9, color:t.waiting?COLORS.amber:COLORS.dim }}>{t.waiting||"–"}</span>
            </div>
          ))}
          <div style={{ marginTop:8, paddingTop:8, borderTop:`1px solid ${COLORS.border}` }}>
            <div style={{ fontSize:9, color:COLORS.muted, marginBottom:4 }}>lock graph</div>
            <div style={{ fontSize:9.5, color:COLORS.text, lineHeight:1.8 }}>
              <span style={{ color:COLORS.amber }}>mutex-A</span><span style={{ color:COLORS.muted }}> held by </span><span style={{ color:COLORS.green }}>main(1)</span><span style={{ color:COLORS.muted }}> ← blocked: </span><span style={{ color:COLORS.red }}>worker-1(2)</span>
            </div>
          </div>
        </div>
      </Box>
      <Box title="▸ Lock Events" flex={1}><Timeline events={data.timeline.filter(e=>e.cat==="lock")}/></Box>
    </div>
  );
}

function IOView({ data }) {
  const { ioReadHistory, ioWriteHistory, ioFiles, ioTotals, ioLatencyBuckets } = data;
  const maxBucket=Math.max(...ioLatencyBuckets.map(b=>Math.max(b.read,b.write)),1);
  const maxOps=Math.max(...ioFiles.map(f=>f.reads+f.writes),1);
  const typeColor=t=>t==="db"?COLORS.purple:t==="log"?COLORS.cyan:t==="cfg"?COLORS.amber:t==="tmp"?COLORS.muted:COLORS.pink;
  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>
      <div style={{ display:"flex", flexDirection:"column", flex:2.2, gap:1 }}>
        <Box title="▸ Throughput — read (cyan) · write (orange)" flex={1}><DualSparkline readH={ioReadHistory} writeH={ioWriteHistory}/></Box>
        <Box title="▸ Top Files" flex={2.5}>
          <div style={{ padding:"4px 12px", display:"flex", flexDirection:"column", gap:5 }}>
            <div style={{ display:"flex", fontSize:9, color:COLORS.muted, marginBottom:2 }}><span style={{ width:24 }}> </span><span style={{ flex:1 }}>PATH</span><span style={{ width:44, textAlign:"right" }}>OPS</span><span style={{ width:56, textAlign:"right" }}>BYTES</span><span style={{ width:52, textAlign:"right" }}>LAT</span><span style={{ width:48, textAlign:"right" }}>FSYNC</span></div>
            {ioFiles.map((f,i)=>{ const ops=f.reads+f.writes; return (
              <div key={i}><div style={{ display:"flex", alignItems:"center", gap:6, fontSize:9.5 }}>
                <span style={{ fontSize:8, color:typeColor(f.type), width:24, border:`1px solid ${typeColor(f.type)}44`, padding:"0 2px", borderRadius:2, textAlign:"center", flexShrink:0 }}>{f.type}</span>
                <span style={{ flex:1, color:COLORS.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.path}</span>
                <span style={{ width:44, textAlign:"right", color:COLORS.bright }}>{ops}</span>
                <span style={{ width:56, textAlign:"right", color:COLORS.muted }}>{fmt(f.bytes)}</span>
                <span style={{ width:52, textAlign:"right", color:f.latency>5?COLORS.red:f.latency>1?COLORS.amber:COLORS.green }}>{f.latency.toFixed(1)}ms</span>
                <span style={{ width:48, textAlign:"right", color:f.fsyncs>10?COLORS.red:f.fsyncs>0?COLORS.amber:COLORS.dim }}>{f.fsyncs>0?`${f.fsyncs} ⚡`:"–"}</span>
              </div><div style={{ height:3, backgroundColor:COLORS.bg, marginTop:2, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(ops/maxOps)*100}%`, height:"100%", background:`linear-gradient(90deg, ${COLORS.cyan}88, ${COLORS.orange}88)`, transition:"width 0.4s" }}/></div></div>
            );})}
          </div>
        </Box>
        <Box title="▸ Latency Distribution" flex={1.4}>
          <div style={{ padding:"6px 12px", display:"flex", flexDirection:"column", gap:4 }}>
            {ioLatencyBuckets.map((b,i)=>(
              <div key={i} style={{ display:"flex", alignItems:"center", gap:6, fontSize:9.5 }}>
                <span style={{ width:48, color:COLORS.muted, flexShrink:0 }}>{b.label}</span>
                <div style={{ flex:1, display:"flex", flexDirection:"column", gap:1 }}>
                  <div style={{ height:5, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(b.read/maxBucket)*100}%`, height:"100%", backgroundColor:COLORS.cyan, opacity:0.8, transition:"width 0.4s" }}/></div>
                  <div style={{ height:5, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(b.write/maxBucket)*100}%`, height:"100%", backgroundColor:COLORS.orange, opacity:0.8, transition:"width 0.4s" }}/></div>
                </div>
                <span style={{ width:28, textAlign:"right", color:COLORS.cyan,   fontSize:9 }}>{b.read.toFixed(0)}</span>
                <span style={{ width:28, textAlign:"right", color:COLORS.orange, fontSize:9 }}>{b.write.toFixed(0)}</span>
              </div>
            ))}
          </div>
        </Box>
      </div>
      <div style={{ display:"flex", flexDirection:"column", flex:1, gap:1 }}>
        <Box title="▸ I/O Stats" flex={0.9}>
          <div style={{ padding:"6px 12px", display:"flex", flexDirection:"column", gap:5 }}>
            {[{ label:"Total read", value:fmt(ioTotals.readBytes), color:COLORS.cyan },{ label:"Total write", value:fmt(ioTotals.writeBytes), color:COLORS.orange },{ label:"Read ops", value:ioTotals.readOps, color:COLORS.cyan },{ label:"Write ops", value:ioTotals.writeOps, color:COLORS.orange },{ label:"fsyncs", value:ioTotals.fsyncs, color:ioTotals.fsyncs>20?COLORS.red:COLORS.amber },{ label:"File opens", value:ioTotals.opens, color:COLORS.muted },{ label:"I/O wait", value:`${ioTotals.iowait.toFixed(1)}%`, color:ioTotals.iowait>15?COLORS.red:COLORS.green }].map(({label,value,color})=>(
              <div key={label} style={{ display:"flex", justifyContent:"space-between", fontSize:10 }}><span style={{ color:COLORS.muted }}>{label}</span><span style={{ color }}>{value}</span></div>
            ))}
          </div>
        </Box>
        <Box title="▸ Anomalies" flex={0.5}>
          <div style={{ padding:"6px 12px", display:"flex", flexDirection:"column", gap:4 }}>
            {ioTotals.fsyncs>15&&<div style={{ fontSize:9.5, color:COLORS.red }}>⚠ high fsync freq → /data/db</div>}
            <div style={{ fontSize:9.5, color:COLORS.amber }}>⚠ /proc/self/status: polling (×12/s)</div>
            {ioTotals.iowait>15&&<div style={{ fontSize:9.5, color:COLORS.red }}>⚠ I/O wait {ioTotals.iowait.toFixed(1)}% → disk saturated</div>}
            {ioTotals.iowait<=15&&ioTotals.fsyncs<=15&&<div style={{ fontSize:9.5, color:COLORS.green }}>✓ no anomalies</div>}
          </div>
        </Box>
        <Box title="▸ I/O Events" flex={2}><Timeline events={data.timeline.filter(e=>e.cat==="io")}/></Box>
      </div>
    </div>
  );
}

// ─── FD View ─────────────────────────────────────────────────────────────────

function FDView({ data }) {
  const { fds, fdCountHistory, fdEvents } = data;
  const [filter, setFilter] = useState("all");

  const typeColor = { file:COLORS.cyan, socket:COLORS.blue, pipe:COLORS.purple, epoll:COLORS.amber, timer:COLORS.green };
  const typeIcon  = { file:"📄", socket:"🔌", pipe:"⇄", epoll:"⊙", timer:"⏱" };

  const types = ["all","file","socket","pipe","epoll","timer"];
  const filtered = filter==="all" ? fds : fds.filter(f=>f.type===filter);

  // breakdown counts
  const breakdown = Object.fromEntries(["file","socket","pipe","epoll","timer"].map(t=>[t, fds.filter(f=>f.type===t).length]));
  const maxBreakdown = Math.max(...Object.values(breakdown),1);

  // suspicious: very old temp files, high-frequency short-lived fds
  const suspicious = fds.filter(f=>(f.type==="file"&&f.path?.includes("/tmp")&&f.age>600)||(f.age<30&&!f.active));

  const curCount = fdCountHistory[fdCountHistory.length-1];

  return (
    <div style={{ display:"flex", flex:1, gap:1, overflow:"hidden", padding:1 }}>

      {/* Left: fd table */}
      <div style={{ display:"flex", flexDirection:"column", flex:2.5, gap:1 }}>

        {/* sparkline + breakdown */}
        <div style={{ display:"flex", gap:1, flex:"none" }}>
          <Box title="▸ FD Count Over Time" flex={2}>
            <Sparkline history={fdCountHistory} color={COLORS.teal} height={40} label="open fds" value={curCount}/>
          </Box>
          <Box title="▸ Breakdown" flex={1}>
            <div style={{ padding:"6px 10px", display:"flex", flexDirection:"column", gap:4 }}>
              {Object.entries(breakdown).map(([t,c])=>(
                <div key={t} style={{ display:"flex", alignItems:"center", gap:6 }}>
                  <span style={{ width:44, fontSize:9, color:COLORS.muted }}>{t}</span>
                  <div style={{ flex:1, height:7, backgroundColor:COLORS.bg, borderRadius:1, overflow:"hidden" }}><div style={{ width:`${(c/maxBreakdown)*100}%`, height:"100%", backgroundColor:typeColor[t], opacity:0.85, transition:"width 0.4s" }}/></div>
                  <span style={{ width:16, fontSize:9, color:typeColor[t], textAlign:"right" }}>{c}</span>
                </div>
              ))}
            </div>
          </Box>
        </div>

        {/* filter tabs */}
        <div style={{ display:"flex", gap:1, backgroundColor:COLORS.bg, padding:"2px 2px 0", flexShrink:0 }}>
          {types.map(t=>(
            <button key={t} onClick={()=>setFilter(t)} style={{ padding:"2px 10px", fontSize:9, cursor:"pointer", border:`1px solid ${filter===t?COLORS.teal:COLORS.border}`, borderBottom:"none", backgroundColor:filter===t?COLORS.bgPanel:COLORS.bg, color:filter===t?COLORS.teal:COLORS.muted, borderRadius:"2px 2px 0 0", letterSpacing:"0.04em" }}>{t}{t!=="all"?` (${breakdown[t]})`:` (${fds.length})`}</button>
          ))}
        </div>

        {/* fd table */}
        <Box title={null} flex={1} style={{ borderTop:`1px solid ${COLORS.teal}44` }}>
          <div style={{ padding:"4px 10px", display:"flex", flexDirection:"column", gap:0, overflowY:"auto", flex:1 }}>
            <div style={{ display:"flex", fontSize:9, color:COLORS.muted, marginBottom:4, borderBottom:`1px solid ${COLORS.border}`, paddingBottom:3 }}>
              <span style={{ width:28 }}>FD</span>
              <span style={{ width:44 }}>TYPE</span>
              <span style={{ flex:1 }}>DESCRIPTION</span>
              <span style={{ width:56 }}>FLAGS</span>
              <span style={{ width:60, textAlign:"right" }}>BYTES</span>
              <span style={{ width:40, textAlign:"right" }}>AGE</span>
              <span style={{ width:14 }}> </span>
            </div>
            {filtered.map(f=>{
              const isOld = f.age > 3600;
              const isSuspect = f.type==="file"&&f.desc?.includes("/tmp")&&f.age>600;
              return (
                <div key={f.fd} style={{ display:"flex", alignItems:"center", fontSize:9.5, padding:"3px 0", borderBottom:`1px solid ${COLORS.border}22`, backgroundColor:isSuspect?"#fbbf2408":"transparent" }}>
                  <span style={{ width:28, color:COLORS.muted, fontWeight:700 }}>{f.fd}</span>
                  <span style={{ width:44, fontSize:8, color:typeColor[f.type]||COLORS.muted }}>
                    {typeIcon[f.type]||"?"} {f.type}
                  </span>
                  <span style={{ flex:1, color:f.active?COLORS.bright:COLORS.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.desc}</span>
                  <span style={{ width:56, fontSize:8, color:COLORS.dim }}>{f.flags}</span>
                  <span style={{ width:60, textAlign:"right", color:COLORS.muted, fontSize:9 }}>{fmt(f.bytes)}</span>
                  <span style={{ width:40, textAlign:"right", color:isOld?COLORS.amber:COLORS.dim, fontSize:9 }}>{fmtAge(f.age)}</span>
                  <span style={{ width:14, textAlign:"center" }}>
                    {f.active ? <span style={{ color:COLORS.green, fontSize:8 }}>●</span> : <span style={{ color:COLORS.dim, fontSize:8 }}>○</span>}
                  </span>
                </div>
              );
            })}
          </div>
        </Box>
      </div>

      {/* Right column */}
      <div style={{ display:"flex", flexDirection:"column", flex:1, gap:1 }}>

        {/* suspicious / leaks */}
        <Box title="▸ Alerts" flex={0.7}>
          <div style={{ padding:"6px 12px", display:"flex", flexDirection:"column", gap:5 }}>
            {suspicious.length===0 && (
              <div style={{ fontSize:9.5, color:COLORS.green }}>✓ no leaks detected</div>
            )}
            {suspicious.map((f,i)=>(
              <div key={i} style={{ fontSize:9.5, color:COLORS.amber }}>
                ⚠ fd={f.fd} {f.type} open for {fmtAge(f.age)} with no activity
              </div>
            ))}
            {fds.length > 20 && (
              <div style={{ fontSize:9.5, color:COLORS.red }}>
                ⚠ {fds.length} fds open — near the limit
              </div>
            )}
          </div>
        </Box>

        {/* fd stats */}
        <Box title="▸ Stats" flex={0.7}>
          <div style={{ padding:"6px 12px", display:"flex", flexDirection:"column", gap:5 }}>
            {[
              { label:"Total open",     value:fds.length,                                          color:COLORS.teal   },
              { label:"Active now",     value:fds.filter(f=>f.active).length,                     color:COLORS.green  },
              { label:"Sockets",        value:breakdown.socket,                                    color:COLORS.blue   },
              { label:"Files",          value:breakdown.file,                                      color:COLORS.cyan   },
              { label:"Oldest",         value:fmtAge(Math.max(...fds.map(f=>f.age))),              color:COLORS.amber  },
              { label:"Total I/O",      value:fmt(fds.reduce((s,f)=>s+f.bytes,0)),                color:COLORS.muted  },
            ].map(({label,value,color})=>(
              <div key={label} style={{ display:"flex", justifyContent:"space-between", fontSize:10 }}>
                <span style={{ color:COLORS.muted }}>{label}</span>
                <span style={{ color }}>{value}</span>
              </div>
            ))}
          </div>
        </Box>

        {/* fd event stream */}
        <Box title="▸ FD Events" flex={2}>
          <div style={{ padding:"4px 10px", flex:1, overflowY:"hidden", display:"flex", flexDirection:"column", gap:1 }}>
            {fdEvents.slice(0,20).map(e=>(
              <div key={e.id} style={{ display:"flex", gap:8, fontSize:9.5, alignItems:"center" }}>
                <span style={{ color:COLORS.dim, flexShrink:0, width:74 }}>{e.ts}</span>
                <span style={{ color:COLORS.text, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{e.msg}</span>
              </div>
            ))}
          </div>
        </Box>
      </div>
    </div>
  );
}

function TimelineView({ data }) {
  const cc={ syscall:COLORS.cyan, net:COLORS.blue, mem:COLORS.purple, cpu:COLORS.green, lock:COLORS.amber, io:COLORS.orange, fd:COLORS.teal };
  const cl={ syscall:"SYS", net:"NET", mem:"MEM", cpu:"CPU", lock:"LCK", io:"I/O", fd:"FD " };
  return (
    <div style={{ flex:1, overflow:"hidden", padding:1 }}>
      <Box title="▸ Full Event Stream" style={{ height:"100%" }}>
        <div style={{ overflowY:"auto", flex:1, padding:"4px 12px", display:"flex", flexDirection:"column", gap:2 }}>
          {data.timeline.map(e=>(
            <div key={e.id} style={{ display:"flex", gap:10, fontSize:10, alignItems:"center" }}>
              <span style={{ color:COLORS.dim, flexShrink:0, width:80 }}>{e.ts}</span>
              <span style={{ color:cc[e.cat], flexShrink:0, width:28, fontSize:8, border:`1px solid ${cc[e.cat]}44`, padding:"0 3px", borderRadius:2, textAlign:"center" }}>{cl[e.cat]}</span>
              <span style={{ color:COLORS.text }}>{e.msg}</span>
            </div>
          ))}
        </div>
      </Box>
    </div>
  );
}

// ─── App ──────────────────────────────────────────────────────────────────────

export default function App() {
  const data = useSimulatedData();

  useEffect(()=>{
    const handler=e=>{ const map={F1:"overview",F2:"syscalls",F3:"network",F4:"threads",F5:"io",F6:"fd",F7:"timeline"}; if(map[e.key]){ e.preventDefault(); data.setActiveTab(map[e.key]); } };
    window.addEventListener("keydown",handler);
    return ()=>window.removeEventListener("keydown",handler);
  },[data.setActiveTab]);

  const renderView=()=>{
    switch(data.activeTab){
      case "syscalls": return <SyscallView  data={data}/>;
      case "network":  return <NetworkView  data={data}/>;
      case "threads":  return <ThreadView   data={data}/>;
      case "io":       return <IOView       data={data}/>;
      case "fd":       return <FDView       data={data}/>;
      case "timeline": return <TimelineView data={data}/>;
      default:         return <OverviewView data={data}/>;
    }
  };

  return (
    <div style={{ backgroundColor:COLORS.bg, minHeight:"100vh", display:"flex", flexDirection:"column", color:COLORS.text, fontFamily:"'JetBrains Mono',monospace", userSelect:"none" }}>
      <Header tick={data.tick} fdCount={data.fds.length}/>
      <TabBar active={data.activeTab} onChange={data.setActiveTab}/>
      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", gap:1, padding:1 }}>{renderView()}</div>
      <div style={{ borderTop:`1px solid ${COLORS.border}`, padding:"2px 12px", display:"flex", gap:16, fontSize:9, color:COLORS.dim, backgroundColor:"#0a0d11", flexShrink:0 }}>
        <span><span style={{ color:COLORS.cyan }}>F1-F7</span> tabs</span>
        <span><span style={{ color:COLORS.cyan }}>q</span> quit</span>
        <span><span style={{ color:COLORS.cyan }}>p</span> pause</span>
        <span><span style={{ color:COLORS.cyan }}>/</span> filter</span>
        <span><span style={{ color:COLORS.cyan }}>s</span> snapshot</span>
        <span><span style={{ color:COLORS.cyan }}>e</span> export</span>
        <div style={{ flex:1 }}/>
        <span style={{ color:COLORS.dim }}>eBPF kernel 6.8 · sampling 100Hz · overhead &lt;0.5%</span>
      </div>
    </div>
  );
}
