import http.server
import socketserver
import json
import urllib.parse
from pathlib import Path
import sqlite3
import os
import case_logger
import forensic_agent
import forensic_dispatcher  # kept as fallback
import evaluator.api as eval_api
import evaluator.storage as eval_storage

PORT = 8080
BASE_DIR = Path(__file__).resolve().parent
AUTOPSY_DB_PATH = BASE_DIR / "CFReDS_DataLeakage" / "autopsy.db"

class ForensicDispatchHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query_params = dict(urllib.parse.parse_qsl(parsed.query))

        if path in ('/', '/index.html'):
            html_file = BASE_DIR / 'index.html'
            if html_file.exists():
                with open(html_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, 'index.html not found')
                return

        elif path in ('/chat', '/chat.html'):
            html_file = BASE_DIR / 'chat.html'
            if html_file.exists():
                with open(html_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, 'chat.html not found')
                return

        elif path in ('/evaluation', '/evaluation.html'):
            html_file = BASE_DIR / 'evaluation.html'
            if html_file.exists():
                with open(html_file, 'rb') as f:
                    content = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                return
            else:
                self.send_error(404, 'evaluation.html not found')
                return

        elif path == '/api/logs':
            logs = case_logger.get_all_logs()
            self._send_json(logs)
            return

        elif path == '/api/stats':
            stats = case_logger.get_stats()
            self._send_json(stats)
            return

        elif path == '/api/case-info':
            case_info = self._get_autopsy_case_info()
            self._send_json(case_info)
            return

        # Evaluation GET Routes
        elif path == '/api/evaluation/questions':
            res, code = eval_api.handle_get_questions()
            self._send_json(res, status=code)
            return

        elif path.startswith('/api/evaluation/ground-truth/'):
            qid_str = path.split('/')[-1]
            if qid_str.isdigit():
                res, code = eval_api.handle_get_ground_truth(int(qid_str))
                self._send_json(res, status=code)
            else:
                self._send_json({'error': 'Invalid question ID'}, status=400)
            return

        elif path == '/api/evaluation/results':
            res, code = eval_api.handle_get_results(query_params)
            self._send_json(res, status=code)
            return

        elif path.startswith('/api/evaluation/results/'):
            eval_id = path.split('/')[-1]
            res, code = eval_api.handle_get_result_by_id(eval_id)
            self._send_json(res, status=code)
            return

        elif path == '/api/evaluation/summary':
            res, code = eval_api.handle_get_summary()
            self._send_json(res, status=code)
            return

        elif path == '/api/evaluation/agents':
            res, code = eval_api.handle_get_agents()
            self._send_json(res, status=code)
            return

        else:
            # Fallback to serving static files from directory
            super().do_GET()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b'{}'
        try:
            data = json.loads(post_body.decode('utf-8')) if post_body else {}
        except Exception:
            data = {}

        if parsed.path == '/api/logs':
            try:
                query = data.get('query', 'Investigator Inquiry')
                cmd = data.get('planned_command', 'autopsy_tools.query()')
                cmd_type = data.get('command_type', 'MCP_TOOL_CALL')
                params = data.get('parameters', {})
                target = data.get('target_evidence', 'autopsy.db')
                status = data.get('status', 'EXECUTED')
                summary = data.get('result_summary', '')
                
                record = case_logger.log_case_query(
                    query=query,
                    planned_command=cmd,
                    command_type=cmd_type,
                    parameters=params,
                    target_evidence=target,
                    status=status,
                    result_summary=summary
                )
                self._send_json(record, status=201)
            except Exception as e:
                self._send_json({'error': str(e)}, status=400)
            return

        elif parsed.path == '/api/chat':
            try:
                user_msg = data.get('message', '').strip()
                if not user_msg:
                    self._send_json({'error': 'Message cannot be empty'}, status=400)
                    return

                if forensic_agent.GEMINI_API_KEY:
                    chat_res = forensic_agent.answer(user_msg)
                else:
                    chat_res = forensic_dispatcher.dispatch_chat_query(user_msg)
                    chat_res['response'] = (
                        "> ⚠️ **Running in keyword-match mode** — set `GEMINI_API_KEY` for full AI reasoning.\n\n"
                        + chat_res.get('response', '')
                    )

                self._send_json(chat_res, status=200)
            except Exception as e:
                self._send_json({'error': str(e)}, status=500)
            return

        # Evaluation POST Routes
        elif parsed.path == '/api/evaluation/evaluate':
            res, code = eval_api.handle_evaluate(data)
            self._send_json(res, status=code)
            return

        elif parsed.path == '/api/evaluation/evaluate-report':
            res, code = eval_api.handle_evaluate_report(data)
            self._send_json(res, status=code)
            return

        elif parsed.path == '/api/evaluation/run-agent':
            res, code = eval_api.handle_run_agent(data)
            self._send_json(res, status=code)
            return

        else:
            self.send_error(404, 'Endpoint not found')

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _get_autopsy_case_info(self):
        info = {
            "case_name": "CFReDS_DataLeakage",
            "case_number": "CFReDS_DataLeakage",
            "examiner": "Melwin Robinson",
            "db_exists": AUTOPSY_DB_PATH.exists(),
            "db_path": str(AUTOPSY_DB_PATH),
            "db_size_mb": round(AUTOPSY_DB_PATH.stat().st_size / (1024 * 1024), 2) if AUTOPSY_DB_PATH.exists() else 0,
            "total_artifacts": 0,
            "artifact_breakdown": {}
        }
        if AUTOPSY_DB_PATH.exists():
            try:
                conn = sqlite3.connect(str(AUTOPSY_DB_PATH))
                c = conn.cursor()
                c.execute("SELECT count(*) FROM blackboard_artifacts")
                info["total_artifacts"] = c.fetchone()[0]
                
                c.execute("""
                    SELECT bat.type_name, count(*) as cnt 
                    FROM blackboard_artifacts ba 
                    JOIN blackboard_artifact_types bat ON ba.artifact_type_id = bat.artifact_type_id 
                    GROUP BY bat.type_name 
                    ORDER BY cnt DESC
                """)
                info["artifact_breakdown"] = {r[0]: r[1] for r in c.fetchall()}
                conn.close()
            except Exception as e:
                info["error"] = str(e)
        return info

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_server(port=PORT):
    case_logger.init_db()
    eval_storage.seed_benchmark_evaluations()
    with ThreadedTCPServer(("", port), ForensicDispatchHandler) as httpd:
        print(f"============================================================")
        print(f" [!] POLICE FORENSIC INCIDENT DISPATCH SERVER RUNNING")
        print(f" [*] Local UI:           http://localhost:{port}/")
        print(f" [*] Forensic Chat:      http://localhost:{port}/chat.html")
        print(f" [*] Hallucination Eval: http://localhost:{port}/evaluation.html")
        print(f" [*] REST API Logs:      http://localhost:{port}/api/logs")
        print(f" [*] REST Case Info:     http://localhost:{port}/api/case-info")
        print(f" [*] Evaluation API:     http://localhost:{port}/api/evaluation/summary")
        print(f" [*] Case Database:      {AUTOPSY_DB_PATH}")
        print(f"============================================================")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down forensic server.")

if __name__ == '__main__':
    run_server()
