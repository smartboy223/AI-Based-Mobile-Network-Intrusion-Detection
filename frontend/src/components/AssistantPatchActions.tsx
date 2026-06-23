import React, { useMemo } from 'react';
import { CheckCircle2 } from 'lucide-react';
import { useAssistantChat } from '../context/AssistantChatContext';
import { parseMnidsRowPatch } from '../lib/assistantPatch';

type Props = {
  messageContent: string;
};

export function AssistantPatchActions({ messageContent }: Props) {
  const { applyTrafficRowPatch } = useAssistantChat();
  const parsed = useMemo(() => parseMnidsRowPatch(messageContent), [messageContent]);

  if (!parsed || !applyTrafficRowPatch) return null;

  return (
    <div className="mt-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2">
      <p className="text-sm text-emerald-900 mb-2">
        Suggested table update for flow <span className="font-mono">{parsed.flowId}</span>.
        <span className="block mt-1 text-emerald-800/90 text-xs font-normal normal-case tracking-normal">
          If this was your pinned row when you sent the message, the dashboard table was updated automatically and saved
          to this browser (localStorage). Use the button below to apply again if needed.
        </span>
      </p>
      <button
        type="button"
        onClick={() =>
          applyTrafficRowPatch(parsed.flowId, parsed.patch, { fromAssistantButton: true })
        }
        className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-600 text-white text-sm font-bold uppercase tracking-wide hover:bg-emerald-500"
      >
        <CheckCircle2 size={14} aria-hidden />
        Apply to traffic table
      </button>
    </div>
  );
}
