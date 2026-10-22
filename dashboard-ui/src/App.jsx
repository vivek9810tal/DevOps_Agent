import React, { useEffect, useRef, useState } from 'react';
import {
  Play, Terminal, Shield, GitBranch, Search,
  CheckCircle, AlertTriangle, Loader2, Clock,
  Activity, Bug, ChevronRight, Server, Package,
  Zap, Rocket, Box, Tag, ExternalLink, XCircle,
  MinusCircle
} from 'lucide-react';

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000').replace(/\/$/, '');

const STAGE_TEMPLATE = {
  build: { status: 'idle', name: '01 Build', icon: Search, detail: 'Pending', detailColor: 'text-slate-500' },
  scan: { status: 'idle', name: '02 Scan', icon: Shield, detail: 'Pending', detailColor: 'text-slate-500' },
  package: { status: 'idle', name: '03 Package', icon: Box, detail: 'Pending', detailColor: 'text-slate-500' },
  containerize: { status: 'idle', name: '04 Containerize', icon: Package, detail: 'Pending', detailColor: 'text-slate-500' },
  release: { status: 'idle', name: '05 Release', icon: Tag, detail: 'Pending', detailColor: 'text-slate-500' },
  deploy: { status: 'idle', name: '06 Deploy', icon: Server, detail: 'Pending', detailColor: 'text-slate-500' },
  test: { status: 'idle', name: '07 Test', icon: Zap, detail: 'Pending', detailColor: 'text-slate-500' },
  publish: { status: 'idle', name: '08 Publish', icon: Rocket, detail: 'Pending', detailColor: 'text-slate-500' }
};

const THREAT_TEMPLATE = {
  semgrep: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'SEMGREP SAST' },
  gitleaks: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'GITLEAKS SECRETS' },
  trivy: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'TRIVY SCA' },
  trivy_iac: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'TRIVY IaC' },
  grype: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'GRYPE CONTAINER' },
  zap: { status: 'idle', summary: 'No report yet', color: 'text-slate-500', name: 'OWASP ZAP DAST' }

};

const AGENT_TEMPLATE = {
  repo_analysis: { name: 'Repository Analysis', status: 'idle', summary: 'Waiting' },
  build_strategy: { name: 'Build Strategy', status: 'idle', summary: 'Waiting' },
  security_strategy: { name: 'Security Strategy', status: 'idle', summary: 'Waiting' },
  deployment_strategy: { name: 'Container / Deployment', status: 'idle', summary: 'Waiting' },
  test_strategy: { name: 'Test Strategy', status: 'idle', summary: 'Waiting' },
  policy_release: { name: 'Policy / Release', status: 'idle', summary: 'Waiting for Jenkins evidence' }
};

const cloneStages = () =>
  Object.fromEntries(Object.entries(STAGE_TEMPLATE).map(([key, value]) => [key, { ...value }]));

const cloneThreats = () =>
  Object.fromEntries(Object.entries(THREAT_TEMPLATE).map(([key, value]) => [key, { ...value }]));

const cloneAgents = () =>
  Object.fromEntries(Object.entries(AGENT_TEMPLATE).map(([key, value]) => [key, { ...value }]));

const stagePresentation = (status) => {
  switch (status) {
    case 'running':
      return { detail: 'Running', detailColor: 'text-blue-400' };
    case 'success':
      return { detail: 'Completed', detailColor: 'text-emerald-500' };
    case 'failed':
      return { detail: 'Failed', detailColor: 'text-red-400' };
    case 'skipped':
      return { detail: 'Not applicable', detailColor: 'text-amber-400' };
    default:
      return { detail: 'Pending', detailColor: 'text-slate-500' };
  }
};

export default function App() {
  const [repoUrl, setRepoUrl] = useState('https://github.com/vivek9810tal/AIML---Supervised-Learning-Project');
  const [branch, setBranch] = useState('main');
  const [isRunning, setIsRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [startTime, setStartTime] = useState(null);
  const [elapsedTime, setElapsedTime] = useState('00:00');
  const [pipelineStatus, setPipelineStatus] = useState('idle');
  const [activeNode, setActiveNode] = useState('System Idle');
  const [stages, setStages] = useState(cloneStages);
  const [threats, setThreats] = useState(cloneThreats);
  const [agents, setAgents] = useState(cloneAgents);
  const [policyFailures, setPolicyFailures] = useState([]);

  const [jenkinsRun, setJenkinsRun] = useState({
    jobName: '',
    buildNumber: null,
    buildUrl: ''
  });

  const logsEndRef = useRef(null);
  const abortControllerRef = useRef(null);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  useEffect(() => {
    let interval;
    if (isRunning && startTime) {
      interval = setInterval(() => {
        const diff = Math.floor((Date.now() - startTime) / 1000);
        const mins = String(Math.floor(diff / 60)).padStart(2, '0');
        const secs = String(diff % 60).padStart(2, '0');
        setElapsedTime(`${mins}:${secs}`);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isRunning, startTime]);

  useEffect(() => () => abortControllerRef.current?.abort(), []);

  const timestamp = () =>
    new Date().toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    });

  const addLog = (message) => {
    setLogs((prev) => [...prev, `[${timestamp()}] ${message}`]);
  };

  const applyStageEvent = (name, status) => {
    if (!STAGE_TEMPLATE[name]) return;
    const view = stagePresentation(status);

    setStages((prev) => ({
      ...prev,
      [name]: {
        ...prev[name],
        status,
        detail: view.detail,
        detailColor: view.detailColor
      }
    }));

    setActiveNode(`Jenkins Stage: ${STAGE_TEMPLATE[name].name.substring(3)} / ${status.toUpperCase()}`);
    addLog(`Stage ${name}: ${status}`);

    if (name === 'scan' && status === 'running') {
      setThreats((prev) =>
        Object.fromEntries(
          Object.entries(prev).map(([key, value]) => [
            key,
            {
              ...value,
              status: 'running',
              summary: 'Scanner evidence pending',
              color: 'text-blue-400'
            }
          ])
        )
      );
    }
  };

  const markPipelineFailure = (message) => {
    setIsRunning(false);
    setPipelineStatus('error');
    setActiveNode('Execution Failed');
    addLog(`ERROR: ${message}`);
  };

  const threatFromScanner = (key, scanner) => {
    if (!scanner || scanner.executed !== true) {
      return {
        status: 'unavailable',
        summary: 'Not executed / report missing',
        color: 'text-amber-400'
      };
    }

    const findings = scanner.findings ?? 0;
    const critical = scanner.critical ?? 0;
    const high = scanner.high ?? 0;

    let summary = `${findings} finding${findings === 1 ? '' : 's'}`;
    if (key === 'trivy' || key === 'trivy_iac' || key === 'grype') {
      summary += ` · ${critical} critical · ${high} high`;
    } else if (key === 'zap') {
      const medium = scanner.medium ?? 0;
      summary += ` · ${high} high · ${medium} medium`;
    }

    let color = 'text-emerald-500';
    if (critical > 0 || (key === 'zap' && high > 0)) {
      color = 'text-red-400';
    } else if (findings > 0 || high > 0) {
      color = 'text-amber-400';
    }

    return {
      status: 'success',
      summary,
      color
    };
  };

  const fetchReports = async (jobName, buildNumber) => {
    if (!jobName || !buildNumber) {
      addLog('Report retrieval skipped: exact Jenkins run identity is unavailable.');
      return;
    }

    try {
      const endpoint = `${API_BASE_URL}/api/reports/${encodeURIComponent(jobName)}/${buildNumber}`;
      const response = await fetch(endpoint, { cache: 'no-store' });

      if (!response.ok) {
        throw new Error(`Report endpoint returned HTTP ${response.status}`);
      }

      const payload = await response.json();
      const scanners = payload.scanners || {};

      setThreats((prev) => {
        const next = { ...prev };
        for (const key of Object.keys(next)) {
          next[key] = {
            ...next[key],
            ...threatFromScanner(key, scanners[key])
          };
        }
        return next;
      });

      const failures = Array.isArray(payload.policy?.policy_failures)
        ? payload.policy.policy_failures
        : [];

      setPolicyFailures(failures);

      if (failures.length > 0) {
        addLog(`Policy evidence contains ${failures.length} failure condition(s).`);
      } else {
        addLog('Policy summary contains no failure conditions.');
      }
    } catch (error) {
      addLog(`Security report retrieval warning: ${error.message}`);
      setThreats((prev) =>
        Object.fromEntries(
          Object.entries(prev).map(([key, value]) => [
            key,
            {
              ...value,
              status: value.status === 'running' ? 'unavailable' : value.status,
              summary: 'Report unavailable',
              color: 'text-slate-500'
            }
          ])
        )
      );
    }
  };

  const handleEvent = async (data) => {
    if (data.job_name || data.build_number || data.build_url) {
      setJenkinsRun((prev) => ({
        jobName: data.job_name || prev.jobName,
        buildNumber: data.build_number ?? prev.buildNumber,
        buildUrl: data.build_url || prev.buildUrl
      }));
    }

    if (data.type === 'agent') {
      const key = data.name;
      const output = data.output || {};
      const decision = output.decision ? ` · ${output.decision}` : '';
      const ecosystem = output.primary_ecosystem ? ` · ${output.primary_ecosystem}` : '';
      const buildSystem = output.build_system ? ` · ${output.build_system}` : '';

      setAgents((prev) => {
        if (!prev[key]) return prev;
        return {
          ...prev,
          [key]: {
            ...prev[key],
            status: data.status || 'completed',
            summary: `${data.message || 'Completed'}${ecosystem}${buildSystem}${decision}`
          }
        };
      });

      setActiveNode(data.message || `Agent ${key} completed`);
      addLog(`AGENT: ${data.message || key}`);
      return;
    }

    if (data.type === 'status') {
      addLog(data.message);
      setActiveNode(data.message);
      return;
    }

    if (data.type === 'stage') {
      applyStageEvent(data.name, data.status);
      return;
    }

    // Kept only for compatibility with an older API.
    if (data.type === 'tool') {
      if (!data.name || !STAGE_TEMPLATE[data.name]) return;
      setStages((prev) => {
        if (prev[data.name]?.status !== 'idle') return prev;
        const view = stagePresentation('running');
        return {
          ...prev,
          [data.name]: {
            ...prev[data.name],
            status: 'running',
            detail: view.detail,
            detailColor: view.detailColor
          }
        };
      });
      return;
    }

    if (data.type === 'pipeline_complete') {
      setIsRunning(false);
      setPipelineStatus('success');
      setActiveNode(`Jenkins ${data.result || 'SUCCESS'}`);
      addLog(`Jenkins build completed with result: ${data.result || 'SUCCESS'}.`);

      await fetchReports(
        data.job_name || jenkinsRun.jobName,
        data.build_number ?? jenkinsRun.buildNumber
      );
      return;
    }

    if (data.type === 'error') {
      setJenkinsRun((prev) => ({
        jobName: data.job_name || prev.jobName,
        buildNumber: data.build_number ?? prev.buildNumber,
        buildUrl: data.build_url || prev.buildUrl
      }));

      if (data.job_name && data.build_number) {
        await fetchReports(data.job_name, data.build_number);
      }

      markPipelineFailure(data.message || 'Unknown pipeline error');
    }
  };

  const consumeSseStream = async (response) => {
    if (!response.body) {
      throw new Error('The API response did not contain a streaming body.');
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      buffer += decoder.decode(value || new Uint8Array(), { stream: !done });

      const events = buffer.split(/\r?\n\r?\n/);
      buffer = events.pop() || '';

      for (const eventBlock of events) {
        const dataLines = eventBlock
          .split(/\r?\n/)
          .filter((line) => line.startsWith('data:'))
          .map((line) => line.slice(5).trimStart());

        if (!dataLines.length) continue;

        try {
          const data = JSON.parse(dataLines.join('\n'));
          await handleEvent(data);
        } catch (error) {
          addLog(`Could not parse backend event: ${error.message}`);
        }
      }

      if (done) break;
    }
  };

  const runPipeline = async () => {
    const cleanRepo = repoUrl.trim();
    const cleanBranch = branch.trim();

    if (!cleanRepo || !cleanBranch) {
      setPipelineStatus('error');
      setActiveNode('Validation Failed');
      setLogs([`[${timestamp()}] Repository URL and branch are required.`]);
      return;
    }

    abortControllerRef.current?.abort();
    const controller = new AbortController();
    abortControllerRef.current = controller;

    setIsRunning(true);
    setPipelineStatus('running');
    setStartTime(Date.now());
    setElapsedTime('00:00');
    setLogs([]);
    setActiveNode('Initializing LangGraph supervisor...');
    setStages(cloneStages());
    setThreats(cloneThreats());
    setAgents(cloneAgents());
    setPolicyFailures([]);
    setJenkinsRun({ jobName: '', buildNumber: null, buildUrl: '' });

    try {
      const response = await fetch(`${API_BASE_URL}/api/run-pipeline`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream'
        },
        body: JSON.stringify({
          repo_url: cleanRepo,
          branch: cleanBranch
        }),
        signal: controller.signal
      });

      if (!response.ok) {
        let detail = '';
        try {
          const body = await response.json();
          detail = body?.detail ? `: ${JSON.stringify(body.detail)}` : '';
        } catch {
          detail = '';
        }
        throw new Error(`Pipeline API returned HTTP ${response.status}${detail}`);
      }

      await consumeSseStream(response);
    } catch (error) {
      if (error.name === 'AbortError') return;
      markPipelineFailure(error.message);
    } finally {
      if (abortControllerRef.current === controller) {
        abortControllerRef.current = null;
      }
    }
  };

  const getStageColor = (status) => {
    switch (status) {
      case 'running':
        return 'border-blue-500/80 bg-blue-950/20 text-blue-300 shadow-[0_0_15px_rgba(59,130,246,0.25)]';
      case 'success':
        return 'border-emerald-800 bg-[#06140b] text-emerald-500';
      case 'failed':
        return 'border-red-500 bg-red-950/30 text-red-400';
      case 'skipped':
        return 'border-amber-700/70 bg-amber-950/20 text-amber-400';
      default:
        return 'border-emerald-950 bg-[#06140b] text-slate-500';
    }
  };

  const statusLabel =
    pipelineStatus === 'running'
      ? 'System Active'
      : pipelineStatus === 'success'
        ? 'Policy Passed'
        : pipelineStatus === 'error'
          ? 'Pipeline Failed'
          : 'System Idle';

  return (
    <div className="min-h-screen p-4 md:p-8 font-sans bg-[#020604] text-slate-200 selection:bg-emerald-500/30">
      <div className="max-w-7xl mx-auto space-y-6">
        <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-6 shadow-2xl">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 mb-6 border-b border-emerald-900/50 pb-6">
            <div className="flex items-center space-x-4">
              <div className="p-3 bg-[#020604] rounded-lg border border-emerald-900/80 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
                <Shield className="w-8 h-8 text-emerald-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white tracking-tight">Agentic CI/CD Orchestrator</h1>
                <p className="text-sm text-slate-400 font-mono mt-1">
                  LangGraph → Jenkins → Real DevSecOps Evidence
                </p>
              </div>
            </div>

            <div className={`flex items-center space-x-3 bg-[#020604] border ${
              pipelineStatus === 'error'
                ? 'border-red-800'
                : isRunning
                  ? 'border-emerald-500 shadow-[0_0_15px_rgba(16,185,129,0.2)]'
                  : 'border-emerald-900/50'
            } rounded-lg px-4 py-2 transition-all`}>
              {pipelineStatus === 'error'
                ? <XCircle className="w-4 h-4 text-red-400" />
                : <Activity className={`w-4 h-4 ${
                    isRunning
                      ? 'text-emerald-400 animate-pulse'
                      : pipelineStatus === 'success'
                        ? 'text-emerald-500'
                        : 'text-slate-500'
                  }`} />}
              <span className={`text-sm font-bold uppercase tracking-wider ${
                pipelineStatus === 'error'
                  ? 'text-red-400'
                  : isRunning
                    ? 'text-emerald-400'
                    : 'text-slate-400'
              }`}>
                {statusLabel}
              </span>
            </div>
          </div>

          <div className="flex flex-col md:flex-row gap-4 items-end">
            <div className="flex-1 w-full relative">
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                Target Repository
              </label>
              <div className="relative flex items-center">
                <GitBranch className="absolute left-4 w-4 h-4 text-emerald-600" />
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  disabled={isRunning}
                  className="w-full bg-[#020604] border border-emerald-900/50 text-slate-200 pl-11 pr-4 py-3 rounded-lg focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 outline-none transition-all font-mono text-sm shadow-inner disabled:opacity-60"
                />
              </div>
            </div>

            <div className="w-full md:w-48 relative">
              <label className="block text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">
                Branch
              </label>
              <input
                type="text"
                value={branch}
                onChange={(e) => setBranch(e.target.value)}
                disabled={isRunning}
                className="w-full bg-[#020604] border border-emerald-900/50 text-slate-200 px-4 py-3 rounded-lg focus:ring-1 focus:ring-emerald-500 focus:border-emerald-500 outline-none transition-all font-mono text-sm shadow-inner disabled:opacity-60"
              />
            </div>

            <button
              onClick={runPipeline}
              disabled={isRunning}
              className={`flex items-center justify-center space-x-2 px-8 py-3 rounded-lg font-bold transition-all h-[46px] min-w-[160px] ${
                isRunning
                  ? 'bg-[#06140b] text-emerald-700 border border-emerald-900/50 cursor-not-allowed'
                  : 'bg-emerald-500 hover:bg-emerald-400 text-[#020604] shadow-[0_0_20px_rgba(16,185,129,0.3)] hover:shadow-[0_0_25px_rgba(16,185,129,0.5)]'
              }`}
            >
              {isRunning
                ? <Loader2 className="w-4 h-4 animate-spin" />
                : <Play className="w-4 h-4 fill-current" />}
              <span className="uppercase text-xs tracking-wider">
                {isRunning ? 'Executing...' : 'Deploy'}
              </span>
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-5 flex items-center justify-between shadow-lg">
            <div>
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Execution Time
              </p>
              <h3 className="text-2xl font-mono font-bold text-slate-200 mt-1">{elapsedTime}</h3>
            </div>
            <Clock className="w-8 h-8 text-emerald-900" />
          </div>

          <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-5 flex items-center justify-between shadow-lg">
            <div className="min-w-0">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Active Graph / Jenkins State
              </p>
              <h3 className="text-sm font-mono text-emerald-500 mt-2 truncate">
                {activeNode}
              </h3>
            </div>
            <Activity className="w-8 h-8 text-emerald-900 shrink-0 ml-4" />
          </div>

          <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-5 flex items-center justify-between relative overflow-hidden shadow-lg">
            <div className="z-10 min-w-0">
              <p className="text-xs font-bold text-slate-400 uppercase tracking-wider">
                Jenkins Run
              </p>
              {jenkinsRun.jobName ? (
                <>
                  <h3 className="text-sm font-mono font-bold text-slate-200 mt-1 truncate">
                    {jenkinsRun.jobName}
                    {jenkinsRun.buildNumber ? ` #${jenkinsRun.buildNumber}` : ''}
                  </h3>
                  {jenkinsRun.buildUrl && (
                    <a
                      href={jenkinsRun.buildUrl}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center text-xs text-emerald-500 hover:text-emerald-300 mt-2"
                    >
                      Open Jenkins <ExternalLink className="w-3 h-3 ml-1" />
                    </a>
                  )}
                </>
              ) : (
                <h3 className="text-sm font-mono text-slate-500 mt-2">Not started</h3>
              )}
            </div>
            <Bug className="w-16 h-16 text-emerald-900/30 absolute right-[-10px] bottom-[-10px] rotate-12" />
          </div>
        </div>

        <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-6 shadow-lg">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-5">
            Multi-Agent Reasoning Layer
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
            {Object.entries(agents).map(([key, agent]) => (
              <div
                key={key}
                className={`rounded-lg border p-3 ${
                  agent.status === 'completed'
                    ? 'border-emerald-700/70 bg-emerald-950/20'
                    : 'border-emerald-950 bg-[#020604]'
                }`}
              >
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[11px] font-bold text-slate-300 uppercase leading-tight">
                    {agent.name}
                  </span>
                  {agent.status === 'completed'
                    ? <CheckCircle className="w-4 h-4 text-emerald-500 shrink-0" />
                    : <Clock className="w-4 h-4 text-slate-600 shrink-0" />}
                </div>
                <p className={`text-[10px] font-mono leading-relaxed ${
                  agent.status === 'completed' ? 'text-emerald-400' : 'text-slate-600'
                }`}>
                  {agent.summary}
                </p>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl p-6 shadow-lg">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-6">
            Execution Lifecycle
          </h2>

          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
            {Object.entries(stages).map(([key, stage], index) => {
              const StageIcon = stage.icon;

              return (
                <div key={key} className="flex flex-col relative group">
                  <div className={`flex flex-col h-full p-4 rounded-xl border-2 transition-all duration-500 ${getStageColor(stage.status)}`}>
                    <div className="flex items-center justify-between mb-3">
                      <span className="text-[10px] font-bold opacity-60 tracking-wider">
                        0{index + 1}
                      </span>

                      {stage.status === 'running'
                        ? <Loader2 className="w-4 h-4 animate-spin text-blue-400" />
                        : stage.status === 'success'
                          ? <CheckCircle className="w-4 h-4 text-emerald-500" />
                          : stage.status === 'failed'
                            ? <XCircle className="w-4 h-4 text-red-400" />
                            : stage.status === 'skipped'
                              ? <MinusCircle className="w-4 h-4 text-amber-400" />
                              : <StageIcon className="w-4 h-4 opacity-40" />}
                    </div>

                    <h4 className="font-bold text-sm tracking-wide mb-1 leading-tight">
                      {stage.name.substring(3)}
                    </h4>

                    <div className={`text-[10px] font-mono tracking-widest uppercase mt-auto pt-2 border-t border-emerald-900/30 ${stage.detailColor}`}>
                      {stage.detail}
                    </div>
                  </div>

                  {index < Object.keys(stages).length - 1 && (
                    <ChevronRight className="hidden lg:block absolute -right-3 top-1/2 -translate-y-1/2 w-5 h-5 text-emerald-900/50 z-10" />
                  )}
                </div>
              );
            })}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 min-h-[600px]">
          <div className="lg:col-span-2 bg-[#020604] rounded-xl border border-emerald-900/50 flex flex-col shadow-2xl overflow-hidden min-h-[600px]">
            <div className="flex items-center justify-between p-4 border-b border-emerald-900/50 bg-[#06140b]">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-emerald-600" />
                <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Live Jenkins Telemetry
                </h2>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-5 font-mono text-[13px] leading-relaxed space-y-1 custom-scrollbar text-emerald-500">
              {logs.length === 0 ? (
                <div className="text-emerald-900 flex items-center h-full justify-center">
                  Awaiting pipeline trigger event...
                </div>
              ) : (
                logs.map((log, i) => (
                  <div key={i} className="break-all">{log}</div>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </div>

          <div className="bg-[#06140b] border border-emerald-900/50 rounded-xl flex flex-col shadow-2xl overflow-hidden min-h-[600px]">
            <div className="p-5 border-b border-emerald-900/50">
              <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center">
                <AlertTriangle className="w-4 h-4 mr-2 text-amber-500" />
                Security Evidence
              </h2>
            </div>

            <div className="flex-1 p-5 overflow-y-auto custom-scrollbar">
              <div className="space-y-4">
                {Object.entries(threats).map(([key, threat]) => (
                  <div
                    key={key}
                    className="border border-emerald-900/50 rounded-lg bg-[#020604] overflow-hidden"
                  >
                    <div className="p-4">
                      <div className="flex justify-between items-center mb-3 gap-2">
                        <span className="text-xs font-bold text-slate-300 uppercase">
                          {threat.name}
                        </span>

                        <span className={`text-xs px-2 py-1 rounded border flex items-center whitespace-nowrap ${
                          threat.status === 'running'
                            ? 'bg-blue-950/30 text-blue-400 border-blue-900'
                            : threat.status === 'success'
                              ? 'bg-[#06140b] text-emerald-500 border-emerald-900'
                              : threat.status === 'unavailable'
                                ? 'bg-amber-950/20 text-amber-400 border-amber-900'
                                : 'bg-[#020604] text-slate-600 border-emerald-950'
                        }`}>
                          {threat.status === 'running' && (
                            <Loader2 className="w-3 h-3 animate-spin mr-1" />
                          )}
                          {threat.status === 'running'
                            ? 'Running'
                            : threat.status === 'success'
                              ? 'Executed'
                              : threat.status === 'unavailable'
                                ? 'Not executed'
                                : 'Pending'}
                        </span>
                      </div>

                      <p className="text-[10px] text-slate-500 font-mono">
                        reports/{key.replace('_', '-')}-report.json
                      </p>
                    </div>

                    <div className={`px-4 py-2 text-xs font-bold border-t border-emerald-900/50 ${threat.color} bg-[#06140b]`}>
                      {threat.summary}
                    </div>
                  </div>
                ))}
              </div>

              {policyFailures.length > 0 && (
                <div className="mt-5 border border-red-900/70 bg-red-950/20 rounded-lg p-4">
                  <div className="text-xs font-bold text-red-400 uppercase tracking-wider mb-3">
                    Policy Gate Failures
                  </div>
                  <ul className="space-y-2 text-[11px] font-mono text-red-300">
                    {policyFailures.map((item, index) => (
                      <li key={index}>• {item}</li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="text-[10px] leading-relaxed text-slate-600 font-mono mt-5">
                A missing scanner report is shown as not executed, never as zero findings.
                Stage state is driven by Jenkins [UI_STAGE] evidence rather than frontend inference.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}