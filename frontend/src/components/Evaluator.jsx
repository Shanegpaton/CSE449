import { useRef, useState } from "react";

const API_URL = "http://localhost:8000";

export default function Evaluator({ onResult }) {
  const [prompt, setPrompt] = useState("");
  const [code, setCode] = useState("");
  const [language, setLanguage] = useState("python");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const zipInput = useRef(null);

  // Shared by both buttons: send the request, show the report or the error
  async function send(path, options) {
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_URL}${path}`, options);
      const data = await res.json();
      if (!res.ok) {
        // 422 = validation error, 413 = too large, 500 = analysis failure
        const msg = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
        throw new Error(msg || `Request failed (${res.status})`);
      }
      onResult(data);
    } catch (e) {
      setError(
        e.message === "Failed to fetch"
          ? "Can't reach the backend. Start it with: py -3.12 -m uvicorn main:app --reload"
          : e.message
      );
      onResult(null);
    } finally {
      setLoading(false);
    }
  }

  function handleAnalyze() {
    send("/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ prompt, code, language }),
    });
  }

  // A zipped Python project is analyzed as a whole, so taint can be followed across files
  function handleZip(e) {
    const file = e.target.files[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    send("/analyze-project", { method: "POST", body });
    e.target.value = "";
  }

  return (
    <section className="panel">
      <label htmlFor="prompt">Prompt given to the AI</label>
      <textarea id="prompt" rows={3} value={prompt} onChange={(e) => setPrompt(e.target.value)}
        placeholder="AI prompt" />

      <label htmlFor="code">Generated code</label>
      <textarea id="code" className="code" rows={16} value={code} onChange={(e) => setCode(e.target.value)}
        placeholder="Paste the AI-generated code here" spellCheck={false} />

      <div className="row">
        <select value={language} onChange={(e) => setLanguage(e.target.value)} aria-label="Language">
          <option value="python">Python</option>
          <option value="javascript">JavaScript</option>
        </select>
        <button onClick={handleAnalyze} disabled={loading || !code.trim()}>
          {loading ? "Analyzing..." : "Analyze code"}
        </button>
      </div>

      <div className="row">
        <button className="secondary" onClick={() => zipInput.current.click()} disabled={loading}>
          Analyze a Python project (.zip)
        </button>
        <input ref={zipInput} type="file" accept=".zip" onChange={handleZip} hidden aria-label="Project zip file" />
      </div>
      {error && <p className="error">{error}</p>}
    </section>
  );
}
