/* eslint-disable react-refresh/only-export-components */
import { createContext, useContext, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { createPipelineWebSocket } from '../api/client';
import type { PipelineEvent } from '../api/types';
import type { LivePipelineState, PipelineStage, PipelineStageInfo, StageStatus } from '../api/types';
import { USE_MOCK_DATA } from '../config';

interface LiveEventsContextValue {
  pipelineState: LivePipelineState | null;
  connected: boolean;
}

const LiveEventsContext = createContext<LiveEventsContextValue>({
  pipelineState: null,
  connected: false,
});

function isPipelineStage(value: string): value is PipelineStage {
  return (
    value === 'state' ||
    value === 'propose' ||
    value === 'evaluate' ||
    value === 'select' ||
    value === 'token' ||
    value === 'attest' ||
    value === 'verify' ||
    value === 'execute'
  );
}

function upsertStage(
  stages: PipelineStageInfo[],
  stage: PipelineStage,
  status: StageStatus,
  durationMs?: number,
  error?: string,
): PipelineStageInfo[] {
  const next = stages.filter((s) => s.stage !== stage);
  next.push({ stage, status, durationMs, error });
  next.sort((a, b) => a.stage.localeCompare(b.stage));
  return next;
}

function pipelineStateFromDecisionCompleted(event: PipelineEvent): LivePipelineState {
  const proofStatus = event.proofStatus ?? 'pending';
  const executionStatus = event.executionStatus ?? 'skipped';

  const verify: StageStatus = proofStatus === 'failed' ? 'failed' : 'complete';
  const execute: StageStatus =
    verify === 'failed' ? 'pending' : executionStatus === 'failed' ? 'failed' : executionStatus === 'success' ? 'complete' : 'pending';

  const stages: PipelineStageInfo[] = [
    { stage: 'state', status: 'complete' },
    { stage: 'propose', status: 'complete' },
    { stage: 'evaluate', status: 'complete' },
    { stage: 'select', status: 'complete' },
    { stage: 'token', status: 'complete' },
    { stage: 'attest', status: 'complete' },
    { stage: 'verify', status: verify },
    { stage: 'execute', status: execute },
  ];

  return {
    decisionId: event.decisionId,
    policyHash: event.policyHash,
    stateHash: event.stateHash,
    candidateCount: event.candidateCount,
    stages,
    startedAt: Date.now(),
  };
}

export function LiveEventsProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const [pipelineState, setPipelineState] = useState<LivePipelineState | null>(null);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (USE_MOCK_DATA) return;

    function stop() {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
      setConnected(false);
    }

    function connect() {
      stop();

      const ws = createPipelineWebSocket((event) => {
        if (event.type === 'decision_completed') {
          setPipelineState(pipelineStateFromDecisionCompleted(event));
          void queryClient.invalidateQueries({ queryKey: ['decisions'] });
          void queryClient.invalidateQueries({ queryKey: ['metrics'] });
          void queryClient.invalidateQueries({ queryKey: ['alerts'] });
          void queryClient.invalidateQueries({ queryKey: ['incidents'] });
          return;
        }

        if (event.type === 'alert_raised') {
          void queryClient.invalidateQueries({ queryKey: ['alerts'] });
          void queryClient.invalidateQueries({ queryKey: ['incidents'] });
          return;
        }

        if (event.type === 'stage_started' || event.type === 'stage_completed') {
          const stage = event.stage;
          if (!stage || !isPipelineStage(stage)) return;
          const status: StageStatus = event.type === 'stage_started' ? 'active' : 'complete';
          setPipelineState((prev) => {
            const base: LivePipelineState = prev ?? { stages: [] };
            return {
              ...base,
              decisionId: event.decisionId ?? base.decisionId,
              stages: upsertStage(base.stages, stage, status, event.durationMs, event.error),
            };
          });
        }
      });

      if (!ws) return;

      wsRef.current = ws;
      ws.onopen = () => {
        if (mountedRef.current) setConnected(true);
      };
      ws.onclose = () => {
        if (!mountedRef.current) return;
        setConnected(false);
        reconnectTimerRef.current = window.setTimeout(() => {
          if (mountedRef.current) connect();
        }, 2000);
      };
    }

    connect();
    return () => stop();
  }, [queryClient]);

  const value = useMemo(() => ({ pipelineState, connected }), [connected, pipelineState]);
  return <LiveEventsContext.Provider value={value}>{children}</LiveEventsContext.Provider>;
}

export function useLiveEvents() {
  return useContext(LiveEventsContext);
}
