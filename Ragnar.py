# Ragnar.py
# Network Traffic Monitor — main entry point
# Manages WiFi, traffic monitoring, display, and web server

import os
import signal
import threading
import time
import logging
import subprocess
import sys
import atexit

from init_shared import shared_data
from logger import Logger
from wifi_manager import WiFiManager
from env_manager import load_env

logger = Logger(name="mild-viking", level=logging.DEBUG)


class MildViking:
    """Main class for Mild-Viking Network Traffic Monitor."""

    def __init__(self, shared_data):
        self.shared_data = shared_data
        self.wifi_manager = WiFiManager(shared_data)
        self.traffic_monitor = None
        self.display = None
        self.shared_data.ragnar_instance = self
        self.shared_data.headless_mode = False

    def run(self):
        """Main loop — starts traffic monitor and WiFi, then keeps running."""
        logger.info("=" * 70)
        logger.info("MILD-VIKING NETWORK MONITOR STARTING")
        logger.info("=" * 70)

        # Start traffic monitor
        try:
            from traffic_monitor import TrafficMonitor
            self.traffic_monitor = TrafficMonitor(self.shared_data)
            self.traffic_monitor.start()
            self.shared_data.traffic_monitor = self.traffic_monitor
            logger.info("Traffic monitor started")
        except Exception as e:
            logger.error(f"Failed to start traffic monitor: {e}")

        # Start WiFi management (LAN-first: prefers ethernet, manages WiFi fallback)
        logger.info("Starting Wi-Fi management system...")
        self.wifi_manager.start()
        logger.info("Wi-Fi management system started")

        # Main loop
        logger.info("Mild-Viking main loop running...")
        while not self.shared_data.should_exit:
            for _ in range(10):
                if self.shared_data.should_exit:
                    break
                time.sleep(1)

        logger.info("Mild-Viking main loop exited")

    def stop(self):
        """Stop all components gracefully."""
        logger.info("Stopping Mild-Viking...")
        if self.traffic_monitor:
            self.traffic_monitor.stop()
        if hasattr(self, 'wifi_manager'):
            self.wifi_manager.stop()
        self.shared_data.should_exit = True
        self.shared_data.display_should_exit = True
        self.shared_data.webapp_should_exit = True
        logger.info("Mild-Viking stopped")

    @staticmethod
    def start_display():
        """Start the e-paper display thread. Fails gracefully if hardware absent."""
        try:
            from display import Display, handle_exit_display
            display = Display(shared_data)
            display_thread = threading.Thread(
                target=display.run, daemon=True, name="display"
            )
            display_thread.start()
            shared_data.display_instance = display
            return display_thread
        except Exception as e:
            logger.warning(f"Display not started (hardware may be absent): {e}")
            return None


def handle_exit(sig, frame, display_thread, ragnar_thread, web_thread):
    """Clean shutdown on SIGINT / SIGTERM."""
    logger.info("Received exit signal, shutting down...")

    if hasattr(shared_data, 'ragnar_instance') and shared_data.ragnar_instance:
        shared_data.ragnar_instance.stop()

    shared_data.should_exit = True
    shared_data.display_should_exit = True
    shared_data.webapp_should_exit = True

    # Try to clear e-paper display
    try:
        from display import handle_exit_display
        handle_exit_display(sig, frame, display_thread, exit_process=False)
    except Exception:
        pass

    for t in [display_thread, ragnar_thread, web_thread]:
        if t and t.is_alive():
            t.join(timeout=2)

    logger.info("Clean exit complete")
    sys.exit(0)


if __name__ == "__main__":
    load_env()
    logger.info("Starting Mild-Viking Network Monitor")

    try:
        logger.info("Loading configuration...")
        shared_data.load_config()

        # Start web server on port 8000 (uses new webapp.py, not webapp_modern.py)
        web_thread = None
        if shared_data.config.get("websrv", True):
            logger.info("Starting web server on port 8000...")
            try:
                from webapp import run_server
                web_thread = threading.Thread(
                    target=lambda: run_server(shared_data=shared_data, port=8000),
                    daemon=True,
                    name="web-server",
                )
                web_thread.start()
                logger.info("Web server thread started")
            except Exception as e:
                logger.error(f"Web server failed to start: {e}")

        # Start e-paper display
        logger.info("Starting display thread...")
        shared_data.display_should_exit = False
        display_thread = MildViking.start_display()

        # Start main Mild-Viking thread
        logger.info("Starting Mild-Viking thread...")
        ragnar = MildViking(shared_data)
        shared_data.ragnar_instance = ragnar

        if display_thread and hasattr(shared_data, 'display_instance'):
            ragnar.display = shared_data.display_instance

        ragnar_thread = threading.Thread(
            target=ragnar.run, name="ragnar-main"
        )
        ragnar_thread.start()

        signal.signal(signal.SIGINT,
            lambda s, f: handle_exit(s, f, display_thread, ragnar_thread, web_thread))
        signal.signal(signal.SIGTERM,
            lambda s, f: handle_exit(s, f, display_thread, ragnar_thread, web_thread))

        ragnar_thread.join()

    except Exception as e:
        logger.error(f"Fatal error during startup: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
