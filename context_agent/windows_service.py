"""Windows service wrapper; requires pywin32 in the dedicated Python runtime."""
import logging
import threading

import servicemanager
import win32event
import win32service
import win32serviceutil

import agent


class ContextAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "CVE3POContextAgent"
    _svc_display_name_ = "CVE3PO Context Agent (Pilot)"
    _svc_description_ = "Separate CVE3PO pilot context agent"

    def __init__(self, args):
        super().__init__(args)
        self.stop_event = threading.Event()
        self.stopped = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.stop_event.set()
        win32event.SetEvent(self.stopped)

    def SvcDoRun(self):
        try:
            agent.run(agent.load_config(agent.config_path()), self.stop_event)
        except Exception as exc:
            servicemanager.LogErrorMsg("CVE3PO context agent failed: " + str(exc))
            raise


if __name__ == "____main__":
    win32serviceutil.HandleCommandLine(ContextAgentService)
