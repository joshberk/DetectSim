/**
 * Workspace View
 * Main detection engineering workspace
 */

import React, { useState, useEffect } from 'react';
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
} from 'lucide-react';
import { useGame } from '../../context/GameContext';
import { useScenario, useDetection } from '../../hooks';
import { Button, Badge } from '../ui';
import { generateRawLog } from '../../utils/logGenerator';
import { sanitizeHTML } from '../../utils/sanitize';

export const Workspace = () => {
  const { state } = useGame();
  const {
    currentScenario,
    userCode,
    setUserCode,
    exitScenario,
    getHintContent,
    purchaseHint,
  } = useScenario();

  const { results, feedback, isRunning, executeDetection, isCompleted } =
    useDetection(currentScenario);

  const [showRawLogs, setShowRawLogs] = useState(true);
  const [logs, setLogs] = useState([]);
  const [showHints, setShowHints] = useState(false);

  // Initialize logs when scenario changes
  useEffect(() => {
    if (currentScenario?.logs) {
      setLogs(currentScenario.logs);
    }
  }, [currentScenario]);

  // Update logs with detection results
  useEffect(() => {
    if (results) {
      setLogs(results);
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
  };

  const handlePurchaseHint = (index) => {
    const hint = currentScenario.hints?.[index];
    if (hint && purchaseHint(index)) {
      // Hint purchased successfully
    }
  };

  return (
    <div className="h-screen flex flex-col bg-[#0f172a] text-gray-300">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 p-3 flex justify-between items-center shadow-lg z-10">
        <div className="flex items-center gap-4">
          <button
            onClick={exitScenario}
            className="p-2 hover:bg-gray-700 rounded text-gray-400 hover:text-white transition-colors"
          >
            <ChevronRight className="rotate-180" size={20} />
          </button>
          <div>
            <h2 className="font-bold text-white flex items-center gap-2">
              <span className="text-emerald-500">#{currentScenario.id}</span>
              {currentScenario.title}
              {isCompleted && (
                <Badge variant="success" size="sm">
                  Completed
                </Badge>
              )}
            </h2>
            <div className="text-xs text-gray-500 font-mono flex items-center gap-2">
              <span>Level {currentScenario.level}</span>
              <span>•</span>
              <span>{currentScenario.mitre?.technique}</span>
            </div>
          </div>
        </div>

        <div className="flex gap-4 items-center">
          {/* Budget */}
          <div className="flex flex-col items-end mr-4">
            <span className="text-[10px] uppercase text-gray-500 font-bold">
              Budget
            </span>
            <span className="font-mono text-yellow-400 flex items-center gap-1 font-bold">
              <DollarSign size={14} />
              {state.budget}
            </span>
          </div>

          {/* Deploy Button */}
          <Button
            onClick={handleRunDetection}
            disabled={isRunning}
            loading={isRunning}
            icon={Play}
          >
            Deploy Rule
          </Button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden">
        {/* Left Panel: Intel & Logs */}
        <div className="w-1/2 flex flex-col border-r border-gray-700">
          {/* Briefing */}
          <div className="h-1/3 p-6 overflow-y-auto bg-gray-800/50 border-b border-gray-700">
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
                const isFalsePositive = isDetected && !log.malicious;

                return (
                  <div
                    key={log.id}
                    className={`
                      p-2 rounded border-l-2 transition-all relative
                      ${
                        isDetected
                          ? isTruePositive
                            ? 'bg-emerald-900/20 border-emerald-500 text-emerald-100'
                            : 'bg-red-900/20 border-red-500 text-red-100'
                          : 'border-transparent text-gray-400 hover:bg-[#151515]'
                      }
                    `}
                  >
                    {/* Detection Badge */}
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
                      <div className="grid grid-cols-[80px_1fr] gap-x-2 gap-y-1 text-xs pr-20">
                        <div className="text-gray-600 text-right">Time</div>
                        <div className="text-gray-300">{log.timestamp}</div>
                        <div className="text-gray-600 text-right">Process</div>
                        <div className="text-blue-400">
                          {log.image || log.processName}
                        </div>
                        {log.commandLine && (
                          <>
                            <div className="text-gray-600 text-right">CMD</div>
                            <div className="text-yellow-100/80 break-all">
                              {log.commandLine}
                            </div>
                          </>
                        )}
                        {log.user && (
                          <>
                            <div className="text-gray-600 text-right">User</div>
                            <div className="text-purple-300">{log.user}</div>
                          </>
                        )}
                        {log.parentImage && (
                          <>
                            <div className="text-gray-600 text-right">Parent</div>
                            <div className="text-cyan-300">{log.parentImage}</div>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Panel: Code Editor */}
        <div className="w-1/2 flex flex-col bg-[#1e1e1e]">
          {/* Editor Header */}
          <div className="p-3 bg-[#252526] text-gray-400 flex justify-between items-center text-xs border-b border-[#333]">
            <div className="flex items-center gap-2 px-2">
              <Code size={14} className="text-blue-400" />
              <span className="font-bold text-gray-300">detection_rule.yml</span>
            </div>

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

          {/* Hints Panel */}
          {showHints && (
            <div className="p-4 bg-[#2d2d2d] border-b border-[#333] space-y-2">
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
                      <div className="text-sm text-gray-300 font-mono whitespace-pre-wrap">
                        {hintData.content}
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
          <div className="flex-1 relative">
            <textarea
              spellCheck="false"
              value={userCode}
              onChange={(e) => setUserCode(e.target.value)}
              className="w-full h-full bg-[#1e1e1e] text-[#d4d4d4] font-mono text-sm p-6 focus:outline-none resize-none leading-relaxed"
              style={{
                tabSize: 2,
                fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
              }}
              placeholder="# Start writing your Sigma rule here..."
            />
          </div>

          {/* Feedback Panel */}
          {feedback && (
            <div
              className={`
                p-4 border-t animate-in slide-in-from-bottom duration-300
                ${
                  feedback.type === 'error'
                    ? 'bg-red-950/40 border-red-900 text-red-200'
                    : ''
                }
                ${
                  feedback.type === 'warning'
                    ? 'bg-yellow-950/40 border-yellow-900 text-yellow-200'
                    : ''
                }
                ${
                  feedback.type === 'success'
                    ? 'bg-emerald-950/40 border-emerald-900 text-emerald-200'
                    : ''
                }
              `}
            >
              <div className="flex items-start gap-3">
                {feedback.type === 'error' && (
                  <Bug className="mt-1 flex-shrink-0 text-red-500" />
                )}
                {feedback.type === 'warning' && (
                  <AlertCircle className="mt-1 flex-shrink-0 text-yellow-500" />
                )}
                {feedback.type === 'success' && (
                  <CheckCircle className="mt-1 flex-shrink-0 text-emerald-500" />
                )}
                <div>
                  <h4 className="font-bold mb-1 uppercase text-xs tracking-wider">
                    {feedback.message}
                  </h4>
                  <p className="text-sm opacity-90 font-mono">{feedback.details}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Workspace;
