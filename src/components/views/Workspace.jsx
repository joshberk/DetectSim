/**
 * Workspace View
 * Main detection engineering workspace.
 * Mobile: tabbed layout (Logs | Editor). Desktop: side-by-side.
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  ChevronRight,
  DollarSign,
  Play,
  Terminal,
  FileText,
  Code,
  Eye,
  HelpCircle,
  Bug,
  AlertCircle,
  CheckCircle,
  ExternalLink,
  ArrowRight,
  Download,
} from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { useScenario, useDetection } from '../../hooks';
import { Button, Badge } from '../ui';
import { generateRawLog } from '../../utils/logGenerator';
import { sanitizeHTML } from '../../utils/sanitize';
import { exportSigmaRule } from '../../utils/sigmaExport';
import { useToast } from '../../context/ToastContext';
import { CodeEditor } from '../CodeEditor';

export const Workspace = () => {
  const { state } = useGame();
  const { toast } = useToast();
  const {
    currentScenario,
    userCode,
    setUserCode,
    exitScenario,
    getHintContent,
    purchaseHint,
    applyHintToCode,
    getNextScenario,
    goToNextScenario,
  } = useScenario();

  const { results, feedback, isRunning, executeDetection, isCompleted } =
    useDetection(currentScenario);

  const [showRawLogs, setShowRawLogs] = useState(true);
  const [logs, setLogs] = useState([]);
  const [showHints, setShowHints] = useState(false);
  // Mobile tab: 'logs' | 'editor'
  const [mobileTab, setMobileTab] = useState('logs');
  // Track which log IDs were just newly detected (for flash animation)
  const [flashIds, setFlashIds] = useState(new Set());
  const prevResultsRef = useRef(null);

  useEffect(() => {
    if (currentScenario?.logs) {
      setLogs(currentScenario.logs);
    }
  }, [currentScenario]);

  useEffect(() => {
    if (!results) return;

    // Always update the log display
    setLogs(results);

    // Identify newly-detected logs to flash-animate
    const prev = prevResultsRef.current;
    prevResultsRef.current = results;

    if (prev) {
      const prevDetected = new Set(
        prev.filter((l) => l.detected).map((l) => l.id)
      );
      const newlyDetected = new Set(
        results
          .filter((l) => l.detected && !prevDetected.has(l.id))
          .map((l) => l.id)
      );
      if (newlyDetected.size > 0) {
        setFlashIds(newlyDetected);
        const t = setTimeout(() => setFlashIds(new Set()), 700);
        return () => clearTimeout(t);
      }
    }
  }, [results]);

  if (!currentScenario) {
    return (
      <div className="h-screen flex items-center justify-center bg-[#0f172a]">
        <p className="text-gray-500">No scenario selected</p>
      </div>
    );
  }

  const handleRunDetection = () => {
    executeDetection(userCode);
    // Switch to editor tab on mobile so feedback is visible
    setMobileTab('editor');
  };

  const handlePurchaseHint = (index) => {
    const hint = currentScenario.hints?.[index];
    if (hint) purchaseHint(index);
  };

  const handleExport = () => {
    const result = exportSigmaRule(userCode, currentScenario);
    if (result.success) {
      toast.success(`Rule exported as ${result.filename}`, { title: 'Export Complete' });
    } else {
      toast.error(result.error || 'Export failed', { title: 'Export Error' });
    }
  };

  const getVisibleLogFields = (log) => {
    const excludedFields = new Set([
      'id', 'malicious', 'detected', 'classification', 'severity', 'logSource',
    ]);
    return Object.entries(log).filter(
      ([field, value]) =>
        !excludedFields.has(field) && value !== null && value !== undefined
    );
  };

  // ─── Shared Sub-panels ────────────────────────────────────────────────────

  const LogPanel = () => (
    <div className="flex flex-col h-full min-h-0">
      {/* Briefing */}
      <div className="p-4 sm:p-6 overflow-y-auto bg-gray-800/50 border-b border-gray-700 max-h-[30vh] sm:h-1/3">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2 text-blue-400">
            <FileText size={16} />
            <span className="uppercase tracking-widest text-xs font-bold">
              Mission Briefing
            </span>
          </div>
          {currentScenario.mitre?.url && (
            <a
              href={currentScenario.mitre.url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-xs text-gray-500 hover:text-blue-400 flex items-center gap-1"
            >
              MITRE ATT&CK <ExternalLink size={10} />
            </a>
          )}
        </div>
        <div
          className="prose-cyber text-sm"
          dangerouslySetInnerHTML={{
            __html: sanitizeHTML(currentScenario.briefing),
          }}
        />
      </div>

      {/* Log Viewer */}
      <div className="flex-1 bg-black flex flex-col min-h-0">
        <div className="p-2 bg-[#1a1a1a] border-b border-[#333] flex justify-between items-center text-xs">
          <div className="flex items-center gap-2 text-gray-400 px-2">
            <Terminal size={14} />
            <span className="font-mono font-bold uppercase">
              Log Stream ({currentScenario.logSource})
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-gray-500">{logs.length} Events</div>
            <button
              onClick={() => setShowRawLogs(!showRawLogs)}
              className="flex items-center gap-1 text-[10px] bg-[#333] hover:bg-[#444] px-3 py-1.5 rounded text-white transition-colors"
            >
              {showRawLogs ? (
                <Eye size={12} className="text-blue-400" />
              ) : (
                <FileText size={12} />
              )}
              {showRawLogs ? 'Show Parsed' : 'Show Raw'}
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-auto p-4 space-y-1 font-mono text-[11px] leading-relaxed bg-[#0c0c0c]">
          {logs.map((log) => {
            const isDetected = log.detected;
            const isTruePositive = isDetected && log.malicious;

            return (
              <div
                key={log.id}
                className={`
                  p-2 rounded border-l-2 transition-colors relative
                  ${
                    isDetected
                      ? isTruePositive
                        ? `bg-emerald-900/20 border-emerald-500 text-emerald-100${
                            flashIds.has(log.id) ? ' animate-flash-new-tp' : ''
                          }`
                        : `bg-red-900/20 border-red-500 text-red-100${
                            flashIds.has(log.id) ? ' animate-flash-new-fp' : ''
                          }`
                      : 'border-transparent text-gray-400 hover:bg-[#151515]'
                  }
                `}
              >
                {isDetected && (
                  <div
                    className={`absolute right-2 top-2 px-2 py-0.5 rounded text-[9px] uppercase font-bold tracking-wider ${
                      isTruePositive
                        ? 'bg-emerald-500 text-black'
                        : 'bg-red-500 text-white'
                    }`}
                  >
                    {isTruePositive ? 'MATCH (TP)' : 'MATCH (FP)'}
                  </div>
                )}

                {showRawLogs ? (
                  <div className="break-all whitespace-pre-wrap font-mono opacity-90 pr-20">
                    <span className="text-gray-600 select-none mr-2">$</span>
                    {generateRawLog(log)}
                  </div>
                ) : (
                  <div className="grid grid-cols-[120px_1fr] gap-x-2 gap-y-1 text-xs pr-20">
                    {getVisibleLogFields(log).map(([field, value]) => (
                      <React.Fragment key={`${log.id}-${field}`}>
                        <div className="text-gray-600 text-right">{field}</div>
                        <div className="text-gray-300 break-all">{String(value)}</div>
                      </React.Fragment>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );

  const EditorPanel = () => (
    <div className="flex flex-col h-full bg-[#1e1e1e]">
      {/* Editor Header */}
      <div className="p-3 bg-[#252526] text-gray-400 flex justify-between items-center text-xs border-b border-[#333]">
        <div className="flex items-center gap-2 px-2">
          <Code size={14} className="text-blue-400" />
          <span className="font-bold text-gray-300">detection_rule.yml</span>
        </div>
        <div className="flex items-center gap-2">
          {/* Export button */}
          <button
            onClick={handleExport}
            title="Export rule as .yml"
            className="flex items-center gap-1 px-2 py-1.5 rounded hover:bg-[#333] text-gray-500 hover:text-emerald-400 transition-colors"
          >
            <Download size={13} />
            <span className="hidden sm:inline text-[11px]">Export</span>
          </button>

          <button
            onClick={() => setShowHints(!showHints)}
            className="flex items-center gap-2 px-3 py-1.5 rounded hover:bg-[#333] transition-colors"
          >
            <HelpCircle
              size={14}
              className={showHints ? 'text-yellow-400' : 'text-gray-500'}
            />
            <span>Hints</span>
          </button>
        </div>
      </div>

      {/* Hints Panel */}
      {showHints && (
        <div className="p-4 bg-[#2d2d2d] border-b border-[#333] space-y-2 max-h-64 overflow-y-auto">
          <div className="text-xs text-gray-400 uppercase font-bold mb-2">
            Available Hints
          </div>
          {currentScenario.hints?.map((hint, index) => {
            const hintData = getHintContent(index);
            return (
              <div
                key={index}
                className="p-3 bg-[#1e1e1e] rounded border border-[#444]"
              >
                {hintData?.isPurchased ? (
                  <div className="space-y-3">
                    <div className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
                      {hintData.content}
                    </div>
                    {hint.isSolution && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => applyHintToCode(index)}
                      >
                        Apply to Editor
                      </Button>
                    )}
                  </div>
                ) : (
                  <div className="flex items-center justify-between">
                    <span className="text-gray-500 text-sm">
                      Hint {index + 1}
                      {hint.isSolution && ' (Full Solution)'}
                    </span>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => handlePurchaseHint(index)}
                      disabled={state.budget < hint.cost}
                    >
                      <DollarSign size={12} className="mr-1" />
                      {hint.cost}
                    </Button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Code Editor */}
      <div className="flex-1 relative min-h-0">
        <CodeEditor
          value={userCode}
          onChange={setUserCode}
          readOnly={false}
        />
      </div>

      {/* Feedback Panel */}
      {feedback && (
        <div
          className={`
            p-4 border-t animate-in slide-in-from-bottom duration-300 flex-shrink-0
            ${feedback.type === 'error'    ? 'bg-red-950/40 border-red-900 text-red-200' : ''}
            ${feedback.type === 'warning'  ? 'bg-yellow-950/40 border-yellow-900 text-yellow-200' : ''}
            ${feedback.type === 'success'  ? 'bg-emerald-950/40 border-emerald-900 text-emerald-200' : ''}
          `}
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-start gap-3">
              {feedback.type === 'error'   && <Bug       className="mt-1 flex-shrink-0 text-red-500"     size={18} />}
              {feedback.type === 'warning' && <AlertCircle className="mt-1 flex-shrink-0 text-yellow-500" size={18} />}
              {feedback.type === 'success' && <CheckCircle className="mt-1 flex-shrink-0 text-emerald-500" size={18} />}
              <div>
                <h4 className="font-bold mb-1 uppercase text-xs tracking-wider">
                  {feedback.message}
                </h4>
                <p className="text-sm opacity-90 font-mono">{feedback.details}</p>
              </div>
            </div>

            {feedback.type === 'success' && (
              <div className="flex gap-2 flex-shrink-0">
                {getNextScenario() ? (
                  <Button onClick={goToNextScenario} variant="primary" size="sm" icon={ArrowRight}>
                    Next Scenario
                  </Button>
                ) : (
                  <Button onClick={exitScenario} variant="outline" size="sm">
                    Back to Dashboard
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );

  // ─── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="h-screen flex flex-col bg-[#0f172a] text-gray-300">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 p-3 flex justify-between items-center shadow-lg z-10 flex-shrink-0">
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={exitScenario}
            className="p-2 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors flex-shrink-0"
            aria-label="Back to Dashboard"
          >
            <ChevronRight className="rotate-180" size={20} />
          </button>
          <div className="min-w-0">
            <h2 className="font-bold text-white flex items-center gap-2 flex-wrap">
              <span className="text-emerald-500 font-mono text-sm">#{currentScenario.id}</span>
              <span className="truncate">{currentScenario.title}</span>
              {isCompleted && (
                <Badge variant="success" size="sm">Completed</Badge>
              )}
            </h2>
            <div className="text-xs text-gray-500 font-mono flex items-center gap-2">
              <span>Level {currentScenario.level}</span>
              <span>•</span>
              <span className="truncate">{currentScenario.mitre?.technique}</span>
            </div>
          </div>
        </div>

        <div className="flex gap-3 items-center flex-shrink-0">
          {/* Budget */}
          <div className="flex flex-col items-end">
            <span className="text-[10px] uppercase text-gray-500 font-bold">Budget</span>
            <span className="font-mono text-yellow-400 flex items-center gap-1 font-bold text-sm">
              <DollarSign size={12} />
              {state.budget}
            </span>
          </div>

          {/* Deploy Button */}
          <Button onClick={handleRunDetection} disabled={isRunning} loading={isRunning} icon={Play}>
            <span className="hidden sm:inline">Deploy Rule</span>
            <span className="sm:hidden">Run</span>
          </Button>
        </div>
      </header>

      {/* Mobile Tab Switcher */}
      <div className="sm:hidden flex border-b border-gray-700 bg-gray-800 flex-shrink-0">
        <button
          onClick={() => setMobileTab('logs')}
          className={`flex-1 py-2.5 text-xs font-bold uppercase tracking-wide flex items-center justify-center gap-2 transition-colors ${
            mobileTab === 'logs'
              ? 'text-blue-400 border-b-2 border-blue-400'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          <Terminal size={14} />
          Logs
        </button>
        <button
          onClick={() => setMobileTab('editor')}
          className={`flex-1 py-2.5 text-xs font-bold uppercase tracking-wide flex items-center justify-center gap-2 transition-colors ${
            mobileTab === 'editor'
              ? 'text-purple-400 border-b-2 border-purple-400'
              : 'text-gray-500 hover:text-gray-300'
          }`}
        >
          <Code size={14} />
          Editor
        </button>
      </div>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden min-h-0">
        {/* Desktop: side by side. Mobile: single active tab */}
        <div className={`w-full sm:w-1/2 flex-col border-r border-gray-700 ${mobileTab === 'logs' ? 'flex' : 'hidden sm:flex'}`}>
          <LogPanel />
        </div>
        <div className={`w-full sm:w-1/2 flex-col ${mobileTab === 'editor' ? 'flex' : 'hidden sm:flex'}`}>
          <EditorPanel />
        </div>
      </div>
    </div>
  );
};

export default Workspace;
