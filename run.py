#!/usr/bin/env python3
"""
LeadDrive CRM — Entry Point
==========================
Starts the CRM web server with database initialization.

Usage:
  python run.py              # Start CRM server (default port 8766)
  python run.py --sync       # Run email sync only, then exit
  python run.py --port 8080  # Custom port
"""

import os
import sys
import argparse
import logging

from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("hermes-crm")


def main():
    parser = argparse.ArgumentParser(description="LeadDrive CRM Server")
    parser.add_argument("--port", type=int, default=int(os.getenv("CRM_PORT", "8766")))
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--sync", action="store_true", help="Run email sync only")
    args = parser.parse_args()

    # Initialize database
    from database import init_db
    init_db()

    if args.sync:
        # Sync mode — run email sync and exit
        logger.info("Running Apple Mail sync...")
        from apple_mail_sync import sync_emails
        result = sync_emails(limit=500)
        logger.info("Sync results:")
        for k, v in result.items():
            logger.info("  %s: %s", k, v)
        return

    # Start web server
    logger.info("=" * 50)
    logger.info("  LeadDrive CRM starting on port %d", args.port)
    logger.info("  Dashboard: http://localhost:%d", args.port)
    logger.info("=" * 50)

    import uvicorn
    from api import app

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
