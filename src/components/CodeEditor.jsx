/**
 * CodeEditor Component
 * CodeMirror 6 editor with YAML syntax highlighting and VS Code Dark theme.
 * Replaces the plain textarea in the Workspace.
 */

import React, { useCallback } from 'react';
import CodeMirror from '@uiw/react-codemirror';
import { yaml } from '@codemirror/lang-yaml';
import { vscodeDark } from '@uiw/codemirror-theme-vscode';
import { EditorView } from 'codemirror';

// Custom theme overrides to match DetectSim's palette
const detectSimTheme = EditorView.theme({
  '&': {
    height: '100%',
    fontSize: '13px',
    fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
  },
  '.cm-scroller': {
    fontFamily: "'Fira Code', 'Cascadia Code', Consolas, monospace",
    lineHeight: '1.7',
    padding: '12px 0',
  },
  '.cm-content': {
    padding: '0 16px',
    caretColor: '#10b981',
  },
  '.cm-cursor': {
    borderLeftColor: '#10b981',
    borderLeftWidth: '2px',
  },
  '.cm-activeLine': {
    backgroundColor: 'rgba(16,185,129,0.04)',
  },
  '.cm-activeLineGutter': {
    backgroundColor: 'rgba(16,185,129,0.06)',
  },
  '.cm-gutters': {
    backgroundColor: '#1a1a2e',
    borderRight: '1px solid #2d2d4e',
    color: '#4a4a6a',
    minWidth: '40px',
  },
  '.cm-lineNumbers .cm-gutterElement': {
    padding: '0 8px 0 4px',
    fontSize: '11px',
  },
  '.cm-selectionBackground': {
    backgroundColor: 'rgba(16,185,129,0.2) !important',
  },
  '&.cm-focused .cm-selectionBackground': {
    backgroundColor: 'rgba(16,185,129,0.25) !important',
  },
  '.cm-matchingBracket': {
    color: '#10b981 !important',
    fontWeight: 'bold',
  },
  '.cm-tooltip': {
    backgroundColor: '#1e1e2e',
    border: '1px solid #374151',
    borderRadius: '6px',
  },
});

const extensions = [yaml(), detectSimTheme];

export const CodeEditor = ({ value, onChange, readOnly = false }) => {
  const handleChange = useCallback(
    (val) => {
      if (!readOnly && onChange) {
        onChange(val);
      }
    },
    [readOnly, onChange]
  );

  return (
    <div className="h-full overflow-hidden">
      <CodeMirror
        value={value}
        height="100%"
        theme={vscodeDark}
        extensions={extensions}
        onChange={handleChange}
        readOnly={readOnly}
        basicSetup={{
          lineNumbers: true,
          highlightActiveLineGutter: true,
          highlightSpecialChars: true,
          foldGutter: false,
          drawSelection: true,
          dropCursor: false,
          allowMultipleSelections: false,
          indentOnInput: true,
          syntaxHighlighting: true,
          bracketMatching: true,
          closeBrackets: true,
          autocompletion: false,
          rectangularSelection: false,
          crosshairCursor: false,
          highlightActiveLine: true,
          highlightSelectionMatches: false,
          closeBracketsKeymap: true,
          searchKeymap: false,
          foldKeymap: false,
          completionKeymap: false,
          lintKeymap: false,
        }}
      />
    </div>
  );
};

export default CodeEditor;
