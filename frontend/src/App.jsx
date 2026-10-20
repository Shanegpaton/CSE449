import { useState } from "react";
import Evaluator from "./components/Evaluator.jsx";
import Report from "./components/Report.jsx";

export default function App() {
  const [report, setReport] = useState(null);

  return (
    <div className="app">
      <header className="header">
        <h1>AI Code Security Analyzer</h1>
        <p>Paste code from Copilot, CodeWhisperer, or Cursor and check it for security and correctness problems.</p>
      </header>
      <main className="layout">
        <Evaluator onResult={setReport} />
        <Report report={report} />
      </main>
    </div>
  );
}
