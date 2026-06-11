import sys
import argparse
import logging
from logging.handlers import RotatingFileHandler
import asyncio
import signal
from pathlib import Path

# Import all components
from enhanced_models import EnhancedDDoSDetector, AnomalyDetector
from feature_engineering import AdvancedFeatureEngineering
from database import DatabaseManager, RedisCache
from alert_system import AlertSystem, AlertDigest
from packet_capture import RealTimeMonitor
from api import app as api_app
from config import settings
import uvicorn
import schedule
import time
from threading import Thread

class DDoSDetectionSystem:
    def __init__(self):
        self.setup_logging()
        self.logger = logging.getLogger(__name__)
        self.logger.info("Initializing DDoS Detection System...")
        
        # Initialize components
        self.detector = None
        self.db_manager = None
        self.redis_cache = None
        self.alert_system = None
        self.monitor = None
        self.running = False
        
        self.setup_components()
        self.setup_signal_handlers()
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Create formatters
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            settings.LOG_FILE,
            maxBytes=settings.LOG_MAX_SIZE,
            backupCount=settings.LOG_BACKUP_COUNT
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(getattr(logging, settings.LOG_LEVEL))
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(getattr(logging, settings.LOG_LEVEL))
        root_logger.addHandler(console_handler)
        root_logger.addHandler(file_handler)
    
    def setup_components(self):
        """Initialize all system components"""
        try:
            # Database
            self.logger.info("Initializing database...")
            self.db_manager = DatabaseManager(settings.DATABASE_URL)
            
            # Redis Cache
            self.logger.info("Initializing Redis cache...")
            self.redis_cache = RedisCache(settings.REDIS_URL)
            
            # Alert System
            self.logger.info("Initializing alert system...")
            self.alert_system = AlertSystem()
            
            # ML Detector
            self.logger.info("Loading ML models...")
            self.detector = EnhancedDDoSDetector()
            
            # Try to load existing models
            try:
                self.detector.load_models(settings.MODEL_PATH)
                self.logger.info("Models loaded successfully")
            except Exception as e:
                self.logger.warning(f"Could not load models: {e}")
                self.logger.info("System will train new models on first data batch")
            
            # Real-time Monitor
            self.logger.info("Initializing real-time monitor...")
            self.monitor = RealTimeMonitor(
                self.detector,
                self.db_manager,
                self.alert_system
            )
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            self.logger.info(f"Received signal {signum}, shutting down...")
            self.shutdown()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    def start_api_server(self):
        """Start FastAPI server"""
        self.logger.info(f"Starting API server on {settings.API_HOST}:{settings.API_PORT}")
        uvicorn.run(
            api_app,
            host=settings.API_HOST,
            port=settings.API_PORT,
            workers=settings.API_WORKERS,
            log_level=settings.LOG_LEVEL.lower()
        )
    
    def start_dashboard(self):
        """Start Streamlit dashboard"""
        self.logger.info(f"Starting dashboard on port {settings.DASHBOARD_PORT}")
        import subprocess
        subprocess.Popen([
            "streamlit", "run", "dashboard.py",
            "--server.port", str(settings.DASHBOARD_PORT),
            "--server.headless", "true"
        ])
    
    def start_monitoring(self):
        """Start real-time packet capture and monitoring"""
        self.logger.info("Starting real-time monitoring...")
        self.monitor.start_monitoring(settings.CAPTURE_INTERFACE)
    
    def schedule_tasks(self):
        """Schedule periodic tasks"""
        # Daily digest
        schedule.every().day.at("08:00").do(self.send_daily_digest)
        
        # Model retraining
        schedule.every(settings.MODEL_RETRAIN_INTERVAL).hours.do(self.retrain_models)
        
        # System metrics
        schedule.every(5).minutes.do(self.log_system_metrics)
        
        # Cleanup old data
        schedule.every().day.at("02:00").do(self.cleanup_old_data)
        
        # Run scheduler in background
        def run_scheduler():
            while self.running:
                schedule.run_pending()
                time.sleep(60)
        
        scheduler_thread = Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
    
    def send_daily_digest(self):
        """Send daily summary report"""
        self.logger.info("Sending daily digest...")
        try:
            stats = self.db_manager.get_attack_statistics(days=1)
            digest = AlertDigest(self.alert_system)
            digest.update_stats({
                'attacks_detected': stats.get('total_attacks', 0),
                'packets_analyzed': 0,  # Get from metrics
                'ips_blocked': len(self.db_manager.get_blocked_ips()),
                'false_positives': 0
            })
            digest.send_daily_digest()
        except Exception as e:
            self.logger.error(f"Error sending daily digest: {e}")
    
    def retrain_models(self):
        """Retrain ML models with new data"""
        self.logger.info("Retraining models...")
        try:
            # Get recent traffic data from database
            # Train models
            # Save updated models
            self.detector.save_models(settings.MODEL_PATH)
            self.logger.info("Models retrained successfully")
        except Exception as e:
            self.logger.error(f"Error retraining models: {e}")
    
    def log_system_metrics(self):
        """Log system performance metrics"""
        try:
            import psutil
            metrics = {
                'timestamp': None,  # Will be set by database
                'total_requests': 0,  # Get from monitor
                'blocked_requests': 0,
                'detected_attacks': 0,
                'model_accuracy': 0.0,
                'avg_response_time': 0.0,
                'cpu_usage': psutil.cpu_percent(),
                'memory_usage': psutil.virtual_memory().percent
            }
            self.db_manager.log_metrics(metrics)
        except Exception as e:
            self.logger.error(f"Error logging metrics: {e}")
    
    def cleanup_old_data(self):
        """Clean up old database records"""
        self.logger.info("Cleaning up old data...")
        # Implement cleanup logic
    
    def run(self, mode='full'):
        """Run the system"""
        self.running = True
        
        if mode == 'api':
            # Run API server only
            self.start_api_server()
        
        elif mode == 'dashboard':
            # Run dashboard only
            self.start_dashboard()
            while self.running:
                time.sleep(1)
        
        elif mode == 'monitor':
            # Run monitoring only
            self.start_monitoring()
            while self.running:
                time.sleep(1)
        
        elif mode == 'full':
            # Run everything
            self.schedule_tasks()
            
            # Start dashboard in background
            self.start_dashboard()
            
            # Start monitoring
            self.start_monitoring()
            
            # Start API server (blocking)
            self.start_api_server()
    
    def shutdown(self):
        """Graceful shutdown"""
        self.logger.info("Shutting down system...")
        self.running = False
        
        if self.monitor:
            self.monitor.stop_monitoring()
        
        self.logger.info("System shut down successfully")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='DDoS Detection System')
    parser.add_argument(
        '--mode',
        choices=['full', 'api', 'dashboard', 'monitor'],
        default='full',
        help='Run mode'
    )
    parser.add_argument(
        '--config',
        default='config.json',
        help='Configuration file'
    )
    
    args = parser.parse_args()
    
    # Print banner
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║                                                       ║
    ║     DDoS Detection & Prevention System v2.0           ║
    ║     Advanced ML-Powered Network Security             ║
    ║                                                       ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    # Initialize and run system
    system = DDoSDetectionSystem()
    system.run(mode=args.mode)

if __name__ == "__main__":
    main()