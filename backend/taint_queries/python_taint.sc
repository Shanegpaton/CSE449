// Interprocedural taint query for Python. Sent to the Joern server by joern_engine.py
// after importCode() has built the CPG for the submitted code.
//
// Output: one JSON document written to __RESULT_FILE__ (joern_engine.py fills in the path):
//   {"sources": <count>, "sinks": <count>, "flows": [{"rule","kind","path":[{"file","line","code"}]}]}
// rule = sql | cmd | code     kind = input (confirmed user input) | param (function parameter)

def tqEsc(s: String): String = s.flatMap { c =>
  c match {
    case '"'           => "\\\""
    case '\\'          => "\\\\"
    case '\n'          => "\\n"
    case '\r'          => "\\r"
    case '\t'          => "\\t"
    case x if x < ' '  => " "
    case x             => x.toString
  }
}

def tqNode(n: AstNode): String = {
  val file = scala.util.Try(n.file.name.headOption.getOrElse("")).getOrElse("")
  val line = n.lineNumber.getOrElse(-1)
  "{\"file\":\"" + tqEsc(file) + "\",\"line\":" + line + ",\"code\":\"" + tqEsc(n.code) + "\"}"
}

// Sources: where untrusted input enters
def tqRequestData: List[CfgNode] =
  cpg.call.nameExact("<operator>.fieldAccess")
    .code("(flask\\.)?request\\.(args|form|json|values|cookies|headers|data|files|view_args|get_json|get_data)")
    .l
def tqStdin: List[CfgNode] =
  cpg.call.nameExact("input").l ++ cpg.call.nameExact("<operator>.fieldAccess").code("sys\\.argv").l
// Parameters of functions registered with @app.route / @app.get / @bp.post ...
def tqRouteParams: List[CfgNode] =
  cpg.methodRef
    .where(_.astParent.isCall.code("(?s).*\\.(route|get|post|put|delete|patch)\\(.*"))
    .referencedMethod.parameter.nameNot("self").l
def tqSources: List[CfgNode] = tqRequestData ++ tqStdin ++ tqRouteParams
// Weaker source: any function parameter (caller may pass user input)
def tqParams: List[CfgNode] = cpg.method.internal.parameter.nameNot("self").l

// Sinks: first argument of dangerous calls. A parameterized query keeps user
// input in argument 2, so it is not reported.
def tqSql: List[Expression] = cpg.call.name("execute|executemany|executescript").argument(1).l
def tqCmd: List[Expression] =
  cpg.call.name("system|popen").argument(1).l ++
    cpg.call.name("run|call|Popen|check_output|check_call")
      .filter(c => c.argument.exists(a => a.argumentName.contains("shell") && a.code.contains("True")))
      .argument(1).l
def tqCode: List[Expression] = cpg.call.name("eval|exec").argument(1).l

def tqFlows(rule: String, kind: String, sinks: List[Expression], sources: List[CfgNode]): List[String] =
  if (sinks.isEmpty || sources.isEmpty) Nil
  else
    scala.util.Try(sinks.reachableByFlows(sources).l).getOrElse(Nil).map { p =>
      "{\"rule\":\"" + rule + "\",\"kind\":\"" + kind + "\",\"path\":[" + p.elements.map(tqNode).mkString(",") + "]}"
    }

// The result is written to a file in the shared folder, because the server does not
// return println output to the caller.
def tqRun(): String = {
  val out =
    try {
      val rules = List(("sql", tqSql), ("cmd", tqCmd), ("code", tqCode))
      val src   = tqSources
      val par   = tqParams
      val flows = rules.flatMap { case (rule, sinks) =>
        tqFlows(rule, "input", sinks, src) ++ tqFlows(rule, "param", sinks, par)
      }
      val nSinks = rules.map(_._2.size).sum
      "{\"sources\":" + src.size + ",\"sinks\":" + nSinks + ",\"flows\":[" + flows.mkString(",") + "]}"
    } catch {
      case e: Throwable => "{\"error\":\"" + tqEsc(e.toString) + "\"}"
    }
  java.nio.file.Files.write(java.nio.file.Paths.get("__RESULT_FILE__"), out.getBytes("UTF-8"))
  "TQ_WRITTEN"
}

tqRun()
