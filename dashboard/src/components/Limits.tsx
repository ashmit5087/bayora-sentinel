const GROUPS: { title: string; cls: string; items: string[] }[] = [
  { title: "Held", cls: "lim-held", items: [
    "Cross-tenant file, network and credential access from the red worker (P01–P04, P10, P11).",
    "Root, capabilities, writable filesystem, memory and process ceilings, user namespaces (P06–P09, P15).",
    "Direct access to the audit volume and the audit API from the red worker (P12–P14).",
  ] },
  { title: "Held, with a stated limit", cls: "lim-limit", items: [
    "Tamper evidence: a rewrite after the newest signed checkpoint is not detected until the next checkpoint.",
    "A stolen signing key lets an attacker sign a rewritten history.",
    "Forged appends are stopped by access control (P13), not by the chain.",
    "Per-tenant cache slots removed the timing signal measured here, for one model on one machine.",
  ] },
  { title: "Not tested", cls: "lim-none", items: [
    "Anything marked “Not run” in the matrix above.",
    "Prompt-level attacks: jailbreaks and data exfiltration through model output.",
    "Denial of service beyond the memory and process ceilings.",
  ] },
  { title: "Out of scope", cls: "lim-scope", items: [
    "Container escape through a kernel vulnerability (P16). A shared kernel is a residual risk; a microVM or gVisor would reduce it.",
    "P05 uses a decoy file, not a real container-runtime socket.",
    "A compromised host or Docker daemon.",
  ] },
];

export function Limits() {
  return (
    <div className="limits">
      {GROUPS.map((g) => (
        <section key={g.title} className={`lim ${g.cls}`}>
          <h3>{g.title}</h3>
          <ul>{g.items.map((i) => <li key={i}>{i}</li>)}</ul>
        </section>
      ))}
    </div>
  );
}
