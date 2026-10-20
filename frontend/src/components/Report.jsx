const SECTIONS = [
  ["security", "Security risk"],
  ["correctness", "Logic errors"],
  ["context_gaps", "Context gaps"],
  ["hallucinations", "Hallucinated APIs"],
];

const ENGINES = {
  joern: "Joern (interprocedural taint tracking)",
  ast_fallback: "AST fallback (Joern not running)",
  pattern_scan: "Pattern scan",
  none: "Not analyzed",
};

const where = (f) => (f.file ? `${f.file}:${f.line}` : `Line ${f.line}`);

export default function Report({ report }) {
  if (!report) {
    return (
      <section className="panel empty">
        <p>Paste code and select Analyze code to see the report here.</p>
      </section>
    );
  }

  const { verdict, reason, action, steps = [] } = report.recommendation;

  return (
    <section className="panel">
      <div className={`verdict verdict-${verdict.toLowerCase()}`}>
        <strong>{verdict}</strong>
        <span>{reason}</span>
      </div>

      {/* Overall recommendation: one action plus the ordered fixes */}
      <div className="advice">
        <h2>What to do</h2>
        <p>{action}</p>
        {steps.length > 0 && (
          <ol>
            {steps.map((step, i) => (
              <li key={i}>{step}</li>
            ))}
          </ol>
        )}
      </div>

      <p className="engine">
        Engine: {ENGINES[report.engine] || report.engine}
        {report.engine_note && <span className="note"> {report.engine_note}</span>}
      </p>

      {SECTIONS.map(([key, title]) => {
        const findings = report[key].findings;
        return (
          <div key={key} className="section">
            <h2>{title} <span className="count">{findings.length}</span></h2>
            {findings.length === 0 && <p className="none">No issues found.</p>}
            {findings.map((f, i) => (
              <div key={i} className={`finding ${f.severity || ""}`}>
                <div className="finding-head">
                  <span>{where(f)}</span>
                  {f.type && <span>{f.type} ({f.cwe})</span>}
                  {f.severity && <span className="sev">{f.severity}</span>}
                </div>
                <p>{f.message || f.issue}</p>
                {f.path ? (
                  // Joern: every step from the source to the sink
                  <ol className="path-steps">
                    {f.path.map((s, j) => (
                      <li key={j}>
                        <span className="path-loc">{f.file ? `${s.file}:${s.line}` : `line ${s.line}`}</span>
                        <code>{s.code}</code>
                      </li>
                    ))}
                  </ol>
                ) : (
                  f.source_line && (
                    <p className="path">Taint path: input on line {f.source_line} → {f.sink}() on line {f.line}</p>
                  )
                )}
                {f.evidence && <pre>{f.evidence}</pre>}
              </div>
            ))}
          </div>
        );
      })}
    </section>
  );
}
