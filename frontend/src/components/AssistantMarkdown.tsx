import React from 'react';
import ReactMarkdown from 'react-markdown';
import { cn } from '../lib/utils';

type Props = {
  content: string;
  className?: string;
  /** Slightly larger type for full-page assistant tab */
  comfortable?: boolean;
};

/**
 * Renders assistant Markdown with explicit typography and color (no raw HTML).
 */
export function AssistantMarkdown({ content, className, comfortable }: Props) {
  const body = comfortable ? 'text-lg leading-relaxed' : 'text-base leading-relaxed';
  return (
    <div className={className}>
      <ReactMarkdown
        components={{
          h1: ({ children }) => (
            <h1
              className={cn(
                'font-bold text-violet-800 mb-3 mt-1 tracking-tight',
                comfortable ? 'text-2xl' : 'text-xl',
              )}
            >
              {children}
            </h1>
          ),
          h2: ({ children }) => (
            <h2
              className={cn(
                'font-bold text-[var(--accent)] mb-2 mt-3 first:mt-0',
                comfortable ? 'text-xl' : 'text-lg',
              )}
            >
              {children}
            </h2>
          ),
          h3: ({ children }) => (
            <h3
              className={cn(
                'font-semibold text-violet-800 mb-2 mt-2',
                comfortable ? 'text-xl' : 'text-lg',
              )}
            >
              {children}
            </h3>
          ),
          p: ({ children }) => (
            <p className={cn('text-[var(--text-primary)] leading-relaxed mb-2 last:mb-0', body)}>{children}</p>
          ),
          strong: ({ children }) => (
            <strong className="font-bold text-[var(--text-primary)]">{children}</strong>
          ),
          em: ({ children }) => (
            <em className="italic text-sky-800">{children}</em>
          ),
          ul: ({ children }) => (
            <ul className={cn('list-disc pl-4 mb-2 space-y-1 text-[var(--text-soft)]', body)}>{children}</ul>
          ),
          ol: ({ children }) => (
            <ol className={cn('list-decimal pl-4 mb-2 space-y-1 text-[var(--text-soft)]', body)}>{children}</ol>
          ),
          li: ({ children }) => <li className="leading-relaxed">{children}</li>,
          blockquote: ({ children }) => (
            <blockquote
              className={cn(
                'border-l-4 border-violet-500/70 pl-3 my-2 text-[var(--text-secondary)] italic bg-violet-500/5 py-2 rounded-r',
                body,
              )}
            >
              {children}
            </blockquote>
          ),
          code: ({ children, className: codeClass }) => {
            const isBlock = codeClass?.includes('language-');
            if (isBlock) {
              return (
                <code className="block text-sm font-mono bg-[var(--surface-subtle)] border border-[var(--border)] rounded p-2 my-2 overflow-x-auto text-[var(--text-primary)]">
                  {children}
                </code>
              );
            }
            return (
              <code className="text-sm font-mono bg-[var(--surface-hover)] text-[var(--accent)] px-1.5 py-0.5 rounded">
                {children}
              </code>
            );
          },
          pre: ({ children }) => <pre className="my-2 overflow-x-auto">{children}</pre>,
          a: ({ href, children }) => (
            <a
              href={href}
              className={cn('text-[var(--accent)] underline underline-offset-2 hover:text-[var(--accent-hover)]', body)}
              target="_blank"
              rel="noopener noreferrer"
            >
              {children}
            </a>
          ),
          hr: () => <hr className="border-[var(--border)] my-3" />,
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
