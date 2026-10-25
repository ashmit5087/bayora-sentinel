import { useMemo } from "react";
import type { Config, GauntletRun, Status } from "../lib/types";

interface NodeDef { id: string; label: string; sub?: string; x: number; y: number; w: number; h: number; only?: Config }
interface EdgeDef { id: string; from: string; to: string; kind: "legit" | "attack"; probes: string[]; ctrl?: [number, number]; label?: string; only?: Config }

const NODES: NodeDef[] = [
  { id: "metadata", label: "Metadata decoy", x: 200, y: 36, w: 120, h: 34 },
  { id: "internet", label: "Internet", x: 430, y: 36, w: 110, h: 34 },
  { id: "red", label: "Red-team worker", sub: "the attacker's seat", x: 90, y: 140, w: 140, h: 52 },
  { id: "model", label: "Model", x: 510, y: 140, w: 120, h: 52 },
  { id: "gateway", label: "Gateway", sub: "only approved path", x: 300, y: 226, w: 140, h: 52 },
  { id: "blue", label: "Blue-team worker", x: 90, y: 312, w: 140, h: 52 },
  { id: "bluedata", label: "Blue defense files", x: 250, y: 392, w: 140, h: 34 },
  { id: "audit", label: "Audit log", x: 510, y: 312, w: 120, h: 52 },
  { id: "signer", label: "Signer", sub: "holds the key", x: 510, y: 392, w: 120, h: 40, only: "hardened" },
];

const EDGES: EdgeDef[] = [
  { id: "l1", from: "red", to: "gateway", kind: "legit", probes: [] },
  { id: "l2", from: "blue", to: "gateway", kind: "legit", probes: [] },
  { id: "l3", from: "gateway", to: "model", kind: "legit", probes: [] },
  { id: "l4", from: "gateway", to: "audit", kind: "legit", probes: [] },
  { id: "l5", from: "blue", to: "bluedata", kind: "legit", probes: [] },
  { id: "l6", from: "signer", to: "audit", kind: "legit", probes: [], only: "hardened" },
  { id: "a1", from: "red", to: "bluedata", kind: "attack", probes: ["P01"], label: "reads blue files" },
  { id: "a2", from: "red", to: "model", kind: "attack", probes: ["P02"], label: "skips the gateway" },
  { id: "a3", from: "red", to: "blue", kind: "attack", probes: ["P03"], label: "reaches blue" },
  { id: "a4", from: "red", to: "metadata", kind: "attack", probes: ["P04"] },
  { id: "a5", from: "red", to: "internet", kind: "attack", probes: ["P04"], label: "goes outside" },
  { id: "a6", from: "red", to: "gateway", kind: "attack", probes: ["P10"], ctrl: [160, 215], label: "claims to be blue" },
  { id: "a7", from: "red", to: "audit", kind: "attack", probes: ["P12", "P13", "P14"], ctrl: [330, 345], label: "touches the audit log" },
];

const ZONES: { id: string; label: string; x: number; y: number; w: number; h: number }[] = [
  { id: "red_net", label: "red_net", x: 12, y: 104, w: 156, h: 74 },
  { id: "blue_net", label: "blue_net", x: 12, y: 276, w: 330, h: 164 },
  { id: "model_net", label: "model_net", x: 432, y: 104, w: 156, h: 74 },
  { id: "audit_net", label: "audit_net", x: 432, y: 276, w: 156, h: 164 },
  { id: "meta_net", label: "meta_net", x: 130, y: 12, w: 140, h: 48 },
];

type EdgeState = "breached" | "held" | "untested";
const COLOR: Record<EdgeState, string> = { breached: "var(--breach)", held: "var(--held)", untested: "var(--notrun)" };

const node = (id: string) => NODES.find((n) => n.id === id)!;
const center = (id: string): [number, number] => [node(id).x, node(id).y];

function pathD(e: EdgeDef): string {
  const [x1, y1] = center(e.from);
  const [x2, y2] = center(e.to);
  return e.ctrl ? `M${x1},${y1} Q${e.ctrl[0]},${e.ctrl[1]} ${x2},${y2}` : `M${x1},${y1} L${x2},${y2}`;
}

function pointAt(e: EdgeDef, t: number): [number, number] {
  const [x1, y1] = center(e.from);
  const [x2, y2] = center(e.to);
  if (!e.ctrl) return [x1 + (x2 - x1) * t, y1 + (y2 - y1) * t];
  const [cx, cy] = e.ctrl;
  const u = 1 - t;
  return [u * u * x1 + 2 * u * t * cx + t * t * x2, u * u * y1 + 2 * u * t * cy + t * t * y2];
}

/** Path from the source to the point where the attack stops (a held edge never reaches its target). */
function partialD(e: EdgeDef, t: number): string {
  const [x1, y1] = center(e.from);
  const [px, py] = pointAt(e, t);
  if (!e.ctrl) return `M${x1},${y1} L${px},${py}`;
  const [cx, cy] = e.ctrl;
  return `M${x1},${y1} Q${x1 + (cx - x1) * t},${y1 + (cy - y1) * t} ${px},${py}`;
}

function edgeState(e: EdgeDef, run: GauntletRun | undefined): EdgeState {
  const statuses: Status[] = e.probes.map((id) => run?.probes.find((p) => p.id === id)?.status).filter((s): s is Status => !!s);
  if (statuses.includes("fail")) return "breached";
  if (statuses.length && statuses.every((s) => s === "pass")) return "held";
  return "untested";
}

const STOP = 0.55;

export function Topology({ config, run, selected }: { config: Config; run: GauntletRun | undefined; selected: string }) {
  const reduceMotion = typeof window !== "undefined" && window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
  const edges = useMemo(() => EDGES.filter((e) => !e.only || e.only === config), [config]);
  const nodes = useMemo(() => NODES.filter((n) => !n.only || n.only === config), [config]);
  const anySelected = edges.some((e) => e.kind === "attack" && e.probes.includes(selected));

  return (
    <svg viewBox="0 0 600 450" className="topo" role="img" aria-label={`Network diagram of the ${config} build showing which attack paths are open or blocked`}>
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0,0 L10,5 L0,10 z" fill="var(--breach)" />
        </marker>
      </defs>

      {config === "insecure" ? (
        <g>
          <rect x="4" y="4" width="592" height="442" rx="10" className="zone zone-flat" />
          <text x="16" y="440" className="zone-label zone-label-flat">One flat network: every container can reach every other</text>
        </g>
      ) : (
        <g>
          {ZONES.map((z) => (
            <g key={z.id}>
              <rect x={z.x} y={z.y} width={z.w} height={z.h} rx="8" className="zone zone-sealed" />
              <text x={z.x + 8} y={z.y + z.h - 7} className="zone-label">{z.label} (internal)</text>
            </g>
          ))}
        </g>
      )}

      {edges.map((e) => {
        if (e.kind === "legit") {
          const [x1, y1] = center(e.from);
          const [x2, y2] = center(e.to);
          return <line key={e.id} x1={x1} y1={y1} x2={x2} y2={y2} className="edge-legit" />;
        }
        const state = edgeState(e, run);
        const isSel = e.probes.includes(selected);
        const dim = anySelected && !isSel;
        const opacity = dim ? 0.28 : 1;
        const width = isSel ? 4 : 2.5;
        const [bx, by] = pointAt(e, STOP);
        const [bx2, by2] = pointAt(e, STOP + 0.02);
        const angle = (Math.atan2(by2 - by, bx2 - bx) * 180) / Math.PI + 90;
        return (
          <g key={e.id} opacity={opacity}>
            {state === "breached" && <path d={pathD(e)} fill="none" stroke={COLOR.breached} strokeWidth={width} markerEnd="url(#arrow)" />}
            {state === "held" && (
              <>
                <path d={pathD(e)} fill="none" className="edge-closed" />
                <path d={partialD(e, STOP)} fill="none" stroke={COLOR.held} strokeWidth={width} strokeDasharray="7 5" />
                <g transform={`translate(${bx},${by}) rotate(${angle})`}>
                  <line x1="-11" y1="0" x2="11" y2="0" stroke={COLOR.held} strokeWidth="5" strokeLinecap="round" />
                </g>
              </>
            )}
            {state === "untested" && <path d={pathD(e)} fill="none" stroke={COLOR.untested} strokeWidth={2} strokeDasharray="2 5" strokeLinecap="round" />}
            {isSel && e.label && (() => {
              const [lx, ly] = pointAt(e, 0.3);
              const text = state === "breached" ? e.label : `${e.label}: blocked`;
              return (
                <g transform={`translate(${lx},${ly - 10})`}>
                  <rect x={-4} y={-13} width={text.length * 6.6 + 8} height={20} rx="4" fill="#fff" stroke={COLOR[state]} />
                  <text x={0} y={1} className="edge-label" fill={COLOR[state]}>{text}</text>
                </g>
              );
            })()}
            {isSel && !reduceMotion && state !== "untested" && (
              <circle r="6" fill={COLOR[state]} key={`${config}-${selected}-${e.id}`}>
                <animateMotion dur="1.3s" fill="freeze" path={state === "breached" ? pathD(e) : partialD(e, STOP - 0.02)} calcMode="spline" keySplines="0.4 0 0.2 1" keyTimes="0;1" />
              </circle>
            )}
          </g>
        );
      })}

      {nodes.map((n) => (
        <g key={n.id} transform={`translate(${n.x - n.w / 2},${n.y - n.h / 2})`}>
          <rect width={n.w} height={n.h} rx="6" className={`node${n.id === "red" ? " node-red" : ""}`} />
          <text x={n.w / 2} y={n.sub ? n.h / 2 - 3 : n.h / 2 + 4.5} textAnchor="middle" className="node-label">{n.label}</text>
          {n.sub && <text x={n.w / 2} y={n.h / 2 + 13} textAnchor="middle" className="node-sub">{n.sub}</text>}
        </g>
      ))}
    </svg>
  );
}
