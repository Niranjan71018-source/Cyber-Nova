"""Cyber-Nova SOC Command Center Web and WebSocket Server."""

import os
import json
import asyncio
from typing import Set, Dict, Any, Optional
import tornado.web
import tornado.websocket
import tornado.ioloop

from ..orchestrator import Orchestrator
from ..models import Incident, IncidentSeverity, IncidentStatus
from ..scenarios.presets import get_scenario_presets, create_incident_from_preset


class GlobalState:
    """Singleton holding orchestrator and active websocket clients."""
    orchestrator: Orchestrator = Orchestrator()
    ws_clients: Set["CommandCenterWebSocket"] = set()
    current_scenario_key: str = "sql_injection_portal"
    run_task: Optional[asyncio.Task] = None

    @classmethod
    def init_default(cls):
        cls.orchestrator.load_preset(cls.current_scenario_key)
        cls.orchestrator.blackboard.subscribe(cls.broadcast_event)

    @classmethod
    def broadcast_event(cls, event: Dict[str, Any]):
        msg = json.dumps({"type": "event", "payload": event})
        dead_clients = set()
        for client in cls.ws_clients:
            try:
                client.write_message(msg)
            except Exception:
                dead_clients.add(client)
        cls.ws_clients.difference_update(dead_clients)


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render("index.html")


class ScenariosHandler(tornado.web.RequestHandler):
    def get(self):
        presets = get_scenario_presets()
        summary = [
            {
                "key": k,
                "id": v["id"],
                "name": v["name"],
                "cve": v["cve"],
                "severity": v["severity"].value,
                "description": v["description"]
            }
            for k, v in presets.items()
        ]
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"scenarios": summary}))


class SelectScenarioHandler(tornado.web.RequestHandler):
    def post(self):
        data = tornado.escape.json_decode(self.request.body or b"{}")
        key = data.get("scenario_key", "sql_injection_portal")
        GlobalState.current_scenario_key = key
        GlobalState.orchestrator = Orchestrator()
        GlobalState.orchestrator.load_preset(key)
        GlobalState.orchestrator.blackboard.subscribe(GlobalState.broadcast_event)

        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        GlobalState.broadcast_event({"type": "scenario_loaded", "data": snapshot})
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"success": True, "state": snapshot}))


class CustomIncidentHandler(tornado.web.RequestHandler):
    def post(self):
        data = tornado.escape.json_decode(self.request.body or b"{}")
        inc_id = data.get("id", "INC-CUSTOM-01")
        title = data.get("title", "Custom Security Audit Target")
        code = data.get("code", "")
        file_name = data.get("file_name", "custom_target.py")
        logs = data.get("logs", ["Custom incident audit manually queued by security operator."])

        custom_inc = Incident(
            id=inc_id,
            title=title,
            description="Custom security review and automated patch generation target.",
            severity=IncidentSeverity.HIGH,
            status=IncidentStatus.NEW,
            telemetry_logs=logs,
            source_files={file_name: code}
        )

        GlobalState.orchestrator = Orchestrator()
        GlobalState.orchestrator.initialize_incident(custom_inc)
        GlobalState.orchestrator.blackboard.subscribe(GlobalState.broadcast_event)

        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        GlobalState.broadcast_event({"type": "custom_loaded", "data": snapshot})
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"success": True, "state": snapshot}))


class StateHandler(tornado.web.RequestHandler):
    def get(self):
        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps(snapshot))


class StepHandler(tornado.web.RequestHandler):
    async def post(self):
        result = await GlobalState.orchestrator.step_async()
        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"success": True, "result": result, "state": snapshot}))


class RunHandler(tornado.web.RequestHandler):
    async def post(self):
        data = tornado.escape.json_decode(self.request.body or b"{}")
        delay = float(data.get("delay", 0.8))

        if GlobalState.run_task and not GlobalState.run_task.done():
            self.write(json.dumps({"status": "already_running"}))
            return

        async def _run_loop():
            await GlobalState.orchestrator.run_all_async(delay_seconds=delay)

        GlobalState.run_task = asyncio.create_task(_run_loop())
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "started"}))


class StopHandler(tornado.web.RequestHandler):
    def post(self):
        GlobalState.orchestrator.stop()
        if GlobalState.run_task and not GlobalState.run_task.done():
            GlobalState.run_task.cancel()
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "stopped"}))


class ResetHandler(tornado.web.RequestHandler):
    def post(self):
        GlobalState.orchestrator.stop()
        GlobalState.orchestrator = Orchestrator()
        GlobalState.orchestrator.load_preset(GlobalState.current_scenario_key)
        GlobalState.orchestrator.blackboard.subscribe(GlobalState.broadcast_event)
        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        GlobalState.broadcast_event({"type": "reset", "data": snapshot})
        self.set_header("Content-Type", "application/json")
        self.write(json.dumps({"status": "reset", "state": snapshot}))


class ExportReportHandler(tornado.web.RequestHandler):
    def get(self):
        fmt = self.get_argument("format", "markdown")
        if fmt == "json":
            self.set_header("Content-Type", "application/json")
            self.set_header("Content-Disposition", "attachment; filename=incident_dossier.json")
            self.write(json.dumps(GlobalState.orchestrator.blackboard.get_state_snapshot(), indent=2))
        else:
            self.set_header("Content-Type", "text/markdown; charset=utf-8")
            self.set_header("Content-Disposition", "attachment; filename=incident_dossier.md")
            self.write(GlobalState.orchestrator.blackboard.export_markdown_report())


class CommandCenterWebSocket(tornado.websocket.WebSocketHandler):
    def check_origin(self, origin):
        return True

    def open(self):
        GlobalState.ws_clients.add(self)
        # Send initial snapshot upon connection
        snapshot = GlobalState.orchestrator.blackboard.get_state_snapshot()
        self.write_message(json.dumps({"type": "snapshot", "payload": snapshot}))

    def on_close(self):
        GlobalState.ws_clients.discard(self)

    async def on_message(self, message):
        try:
            data = json.loads(message)
            action = data.get("action")
            if action == "step":
                await GlobalState.orchestrator.step_async()
            elif action == "run":
                delay = float(data.get("delay", 0.8))
                asyncio.create_task(GlobalState.orchestrator.run_all_async(delay_seconds=delay))
            elif action == "stop":
                GlobalState.orchestrator.stop()
            elif action == "reset":
                GlobalState.orchestrator = Orchestrator()
                GlobalState.orchestrator.load_preset(GlobalState.current_scenario_key)
                GlobalState.orchestrator.blackboard.subscribe(GlobalState.broadcast_event)
                GlobalState.broadcast_event({
                    "type": "reset",
                    "data": GlobalState.orchestrator.blackboard.get_state_snapshot()
                })
        except Exception as e:
            self.write_message(json.dumps({"type": "error", "error": str(e)}))


def make_app():
    static_path = os.path.join(os.path.dirname(__file__), "static")
    return tornado.web.Application(
        [
            (r"/", MainHandler),
            (r"/api/scenarios", ScenariosHandler),
            (r"/api/incident/select", SelectScenarioHandler),
            (r"/api/incident/custom", CustomIncidentHandler),
            (r"/api/incident/state", StateHandler),
            (r"/api/incident/step", StepHandler),
            (r"/api/incident/run", RunHandler),
            (r"/api/incident/stop", StopHandler),
            (r"/api/incident/reset", ResetHandler),
            (r"/api/incident/export", ExportReportHandler),
            (r"/ws", CommandCenterWebSocket),
            (r"/(.*)", tornado.web.StaticFileHandler, {"path": static_path}),
        ],
        template_path=static_path,
        static_path=static_path,
        debug=False,
    )


def start_server(port: int = 8080):
    GlobalState.init_default()
    app = make_app()
    app.listen(port)
    print(f"[*] Cyber-Nova SOC Command Center running at http://localhost:{port}")
    tornado.ioloop.IOLoop.current().start()


if __name__ == "__main__":
    start_server(8080)
