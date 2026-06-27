"""Flask application factory."""

import os
from pathlib import Path
from flask import Flask, jsonify, request
from prometheus_flask_exporter import PrometheusMetrics

from config import settings, flask_config, prometheus_config
from analyzer.service import AnalysisService
from logging_config import setup_logging, get_logger


logger = get_logger(__name__)


def create_app(test_config: dict | None = None) -> Flask:
    """Create and configure the Flask application."""
    # Setup logging first
    setup_logging()
    
    app = Flask(__name__, 
                template_folder="../templates",
                static_folder="../static")
    
    # Load configuration
    app.config.update(
        SECRET_KEY=flask_config.secret_key,
        JSON_SORT_KEYS=flask_config.json_sort_keys,
        JSONIFY_PRETTYPRINT_REGULAR=flask_config.jsonify_prettyprint_regular,
    )
    
    if test_config:
        app.config.update(test_config)
    
    # Initialize Prometheus metrics
    if prometheus_config.enabled:
        metrics = PrometheusMetrics(app, path=prometheus_config.path)
        metrics.info("app_info", "SIEM Log Analyzer", version="2.0.0")
    
    # Initialize analysis service
    analysis_service = AnalysisService()
    
    # Request logging middleware
    @app.before_request
    def log_request() -> None:
        logger.info("request_started", 
                   method=request.method, 
                   path=request.path,
                   remote_addr=request.remote_addr)
    
    @app.after_request
    def log_response(response) -> None:
        logger.info("request_completed",
                   method=request.method,
                   path=request.path,
                   status_code=response.status_code)
        return response
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        logger.warning("not_found", path=request.path)
        return jsonify(error="Not found"), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        logger.exception("internal_error", path=request.path)
        return jsonify(error="Internal server error"), 500
    
    # Routes
    @app.route("/")
    def dashboard():
        """Main dashboard showing threat analysis."""
        try:
            report = analysis_service.analyze_file(settings.analyzer.log_file_path)
            logger.info("dashboard_loaded", 
                       threats=report.total_ips_analyzed,
                       attempts=report.total_failed_attempts)
            return app.render_template("index.html", report=report.to_dict())
        except FileNotFoundError:
            logger.error("log_file_not_found", path=str(settings.analyzer.log_file_path))
            return app.render_template("index.html", report=None, 
                                     error="Log file not found"), 404
        except Exception as e:
            logger.exception("dashboard_error")
            return app.render_template("index.html", report=None, 
                                     error="Analysis failed"), 500
    
    @app.route("/api/report")
    def api_report():
        """JSON API endpoint for threat report."""
        try:
            report = analysis_service.analyze_file(settings.analyzer.log_file_path)
            return jsonify(report.to_dict())
        except FileNotFoundError:
            return jsonify(error="Log file not found"), 404
        except Exception as e:
            logger.exception("api_report_error")
            return jsonify(error="Analysis failed"), 500
    
    @app.route("/api/summary")
    def api_summary():
        """Quick summary endpoint."""
        try:
            summary = analysis_service.get_threat_summary(settings.analyzer.log_file_path)
            return jsonify(summary)
        except FileNotFoundError:
            return jsonify(error="Log file not found"), 404
        except Exception as e:
            logger.exception("api_summary_error")
            return jsonify(error="Analysis failed"), 500
    
    @app.route("/health")
    def health_check():
        """Health check endpoint for container orchestration."""
        return jsonify(
            status="healthy",
            app=settings.app_name,
            environment=settings.environment,
        )
    
    @app.route("/ready")
    def readiness_check():
        """Readiness check - verifies log file is accessible."""
        log_path = settings.analyzer.log_file_path
        if log_path.exists():
            return jsonify(status="ready", log_file=str(log_path))
        return jsonify(status="not_ready", log_file=str(log_path)), 503
    
    logger.info("application_started", 
               app=settings.app_name,
               environment=settings.environment)
    
    return app


# Create app instance for WSGI servers
app = create_app()


if __name__ == "__main__":
    app.run(
        host=flask_config.host,
        port=flask_config.port,
        debug=flask_config.debug,
    )